#!/usr/bin/env python3
"""
register_constraints.py
-----------------------
Creates and enforces custom org policy constraints requiring specific labels
on all commonly used GCP resource types.

Usage:
    python3 register_constraints.py           # normal run
    python3 register_constraints.py --dry-run # preview only, no changes made

Requirements:
    - gcloud CLI installed and authenticated
    - Organization Policy Administrator role at org level
    - Python 3.6+
"""

import subprocess
import tempfile
import os
import sys
import time
import json

# -------------------------------------------------------
# CONFIGURE THESE
# -------------------------------------------------------
ORG_ID = "897569801571"

# Required label keys - every resource must have ALL of these
REQUIRED_LABELS = ["owner", "env"]

# Enforcement scope - uncomment ONE only:
ENFORCE_SCOPE = ("organization", ORG_ID)
# ENFORCE_SCOPE = ("folder", "YOUR_FOLDER_ID")
# ENFORCE_SCOPE = ("project", "YOUR_PROJECT_ID")

# Enforcement timing:
#   "immediate" - enforce right after each constraint is registered
#   "end"       - register all constraints first, then enforce all at the end
ENFORCE_TIMING = "immediate"
# -------------------------------------------------------

# Set via --dry-run flag, do not edit here
DRY_RUN = "--dry-run" in sys.argv

# Per-resource-type label field paths in CEL.
# IMPORTANT: GCP does not expose the labels field to the org policy CEL
# evaluator for all resource types. Only the ones listed below have been
# confirmed working. The others are handled by the governance scanner.
#
# CONFIRMED WORKING (labels exposed to CEL):
#   compute.googleapis.com/Instance          → resource.labels
#   storage.googleapis.com/Bucket            → resource.labels
#   container.googleapis.com/Cluster         → resource.resourceLabels
#
# BEING TESTED (unknown CEL support - will fail gracefully if not supported):
#   compute.googleapis.com/ForwardingRule    → resource.labels (LB)
#   compute.googleapis.com/InstanceGroupManager → resource.labels (ASG/MIG)
#
# NOT SUPPORTED (labels NOT exposed to CEL - GCP platform limitation):
#   cloudfunctions.googleapis.com/Function     → use governance scanner
#   artifactregistry.googleapis.com/Repository → explicitly excluded by GCP
#   bigquery.googleapis.com/Dataset            → use governance scanner
#   sqladmin.googleapis.com/Instance           → userLabels not exposed
#   run.googleapis.com/Service                 → labels explicitly excluded
#   compute.googleapis.com/Disk                → labels not in supported fields
RESOURCE_CONFIGS = [
    # confirmed working
    {
        "type": "compute.googleapis.com/Instance",
        "label_field": "resource.labels",
    },
    {
        "type": "storage.googleapis.com/Bucket",
        "label_field": "resource.labels",
    },
    {
        "type": "container.googleapis.com/Cluster",
        "label_field": "resource.resourceLabels",
    },
    # being tested - will fail gracefully if CEL doesn't support labels
    {
        "type": "compute.googleapis.com/ForwardingRule",
        "label_field": "resource.labels",
    },
    {
        "type": "compute.googleapis.com/InstanceGroupManager",
        "label_field": "resource.labels",
    },
]


def build_cel_condition(labels: list, label_field: str) -> str:
    """
    Builds a CEL condition using the correct label field path
    for the specific resource type.
    """
    parts = []
    for label in labels:
        parts.append(
            f'!has({label_field}.{label}) || {label_field}.{label} == ""'
        )
    return " || ".join(parts)


def build_constraint_id(resource_type: str) -> str:
    cleaned = resource_type.replace(".googleapis.com/", "/")
    parts = cleaned.split("/")
    suffix = "".join(part.capitalize() for part in parts)
    return f"custom.requireLabels{suffix}"


def build_constraint_yaml(
    org_id: str,
    constraint_id: str,
    resource_type: str,
    condition: str,
    required_labels: list,
) -> str:
    labels_str = ", ".join(required_labels)
    return f"""name: organizations/{org_id}/customConstraints/{constraint_id}
resourceTypes:
  - {resource_type}
actionType: DENY
condition: >-
  {condition}
displayName: "Require labels ({labels_str}) - {resource_type}"
description: >-
  Blocks creation or update of {resource_type} resources missing required
  labels: {labels_str}. All resources must have these label keys present
  and non-empty.
methodTypes:
  - CREATE
  - UPDATE
"""


def run_command(cmd: list) -> tuple:
    print(f"    CMD: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True, result.stdout.strip()
    else:
        return False, result.stderr.strip()


def get_existing_constraint(constraint_id: str, org_id: str) -> dict:
    result = subprocess.run(
        [
            "gcloud", "org-policies", "describe-custom-constraint",
            constraint_id,
            f"--organization={org_id}",
            "--format=json",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
    return None


def constraint_needs_update(existing: dict, condition: str, resource_type: str) -> bool:
    if existing is None:
        return True

    existing_condition = existing.get("condition", "").strip()
    existing_resources = existing.get("resourceTypes", [])

    condition_changed = existing_condition != condition.strip()
    resource_changed = resource_type not in existing_resources

    if condition_changed:
        print(f"    Change detected: condition updated.")
    if resource_changed:
        print(f"    Change detected: resource type changed.")

    return condition_changed or resource_changed


def register_constraint(yaml_content: str, resource_type: str) -> bool:
    if DRY_RUN:
        print(f"    [DRY RUN] Would register constraint for {resource_type}")
        print(f"    [DRY RUN] YAML content:")
        for line in yaml_content.strip().splitlines():
            print(f"              {line}")
        return True

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, prefix="constraint_"
    ) as f:
        f.write(yaml_content)
        tmpfile = f.name
    try:
        success, output = run_command(
            ["gcloud", "org-policies", "set-custom-constraint", tmpfile]
        )
        if success:
            print(f"    Constraint registered.")
        else:
            print(f"    ERROR: {output}")
        return success
    finally:
        os.unlink(tmpfile)


def enforce_constraint(constraint_id: str, scope: tuple) -> bool:
    """
    Enforces the constraint by writing a policy YAML and calling set-policy.
    Uses set-policy instead of enable-enforce (not available in all gcloud versions).
    """
    scope_type, scope_id = scope

    if DRY_RUN:
        print(f"    [DRY RUN] Would enforce {constraint_id} at {scope_type}: {scope_id}")
        return True

    # Build scope name for the policy
    policy_name = f"{scope_type}s/{scope_id}/policies/{constraint_id}"

    policy_yaml = f"""name: {policy_name}
spec:
  rules:
    - enforce: true
"""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, prefix="policy_"
    ) as f:
        f.write(policy_yaml)
        tmpfile = f.name

    try:
        success, output = run_command(
            ["gcloud", "org-policies", "set-policy", tmpfile]
        )
        if success:
            print(f"    Enforced at {scope_type} level: {scope_id}")
        else:
            print(f"    ERROR: {output}")
        return success
    finally:
        os.unlink(tmpfile)


def print_header():
    scope_type, scope_id = ENFORCE_SCOPE
    dry_run_notice = "  *** DRY RUN - NO CHANGES WILL BE MADE ***" if DRY_RUN else ""
    print("=" * 56)
    print("  GCP Label Enforcement - Constraint Registration")
    if dry_run_notice:
        print(dry_run_notice)
    print(f"  Org       : {ORG_ID}")
    print(f"  Scope     : {scope_type} = {scope_id}")
    print(f"  Timing    : {ENFORCE_TIMING}")
    print(f"  Labels    : {', '.join(REQUIRED_LABELS)}")
    print(f"  Resources : {len(RESOURCE_CONFIGS)}")
    print("=" * 56)
    print()


def confirm_proceed() -> bool:
    if DRY_RUN:
        print("DRY RUN mode - no confirmation needed, nothing will change.")
        print()
        return True

    scope_type, scope_id = ENFORCE_SCOPE
    print(f"WARNING: This will enforce label requirements at")
    print(f"  {scope_type} level: {scope_id}")
    print(f"Any resource creation without labels {REQUIRED_LABELS}")
    print(f"will be blocked after enforcement.")
    print()
    answer = input("Continue? (yes/no): ").strip().lower()
    return answer == "yes"


def print_summary(results: list):
    print()
    print("=" * 56)
    dry = " (DRY RUN)" if DRY_RUN else ""
    print(f"  Results{dry}")
    print("=" * 56)
    print(f"  {'Resource':<45} {'Reg':>4} {'Enf':>4}")
    print(f"  {'-'*45} {'----':>4} {'----':>4}")
    for resource_type, reg_ok, enf_ok in results:
        reg_str = "OK  " if reg_ok else "FAIL"
        enf_str = "OK  " if enf_ok else "FAIL"
        print(f"  {resource_type:<45} {reg_str:>4} {enf_str:>4}")
    print()
    total = len(results)
    reg_ok = sum(1 for _, r, _ in results if r)
    enf_ok = sum(1 for _, _, e in results if e)
    print(f"  Registered : {reg_ok}/{total}")
    print(f"  Enforced   : {enf_ok}/{total}")
    print("=" * 56)
    print()
    if DRY_RUN:
        print("To apply for real, run without --dry-run:")
        print("  python3 register_constraints.py")
    else:
        print("Verify:")
        print(f"  gcloud org-policies list-custom-constraints --organization={ORG_ID}")


def main():
    print_header()

    if not confirm_proceed():
        print("Aborted.")
        sys.exit(0)

    print()
    results = []
    registered = []

    # ── Phase 1: Register constraints ──────────────────────
    print("─" * 56)
    print("  PHASE 1 — Registering constraints")
    print("─" * 56)

    for config in RESOURCE_CONFIGS:
        resource_type = config["type"]
        label_field = config["label_field"]
        constraint_id = build_constraint_id(resource_type)
        condition = build_cel_condition(REQUIRED_LABELS, label_field)

        print(f"\n>>> {resource_type}")
        print(f"    ID         : {constraint_id}")
        print(f"    Label field: {label_field}")

        yaml_content = build_constraint_yaml(
            org_id=ORG_ID,
            constraint_id=constraint_id,
            resource_type=resource_type,
            condition=condition,
            required_labels=REQUIRED_LABELS,
        )

        existing = get_existing_constraint(constraint_id, ORG_ID)
        if existing and not constraint_needs_update(existing, condition, resource_type):
            print(f"    No changes - skipping registration.")
            registered.append((resource_type, constraint_id, condition))
            reg_ok = True

            if ENFORCE_TIMING == "immediate":
                print(f"    Ensuring enforcement...")
                enf_ok = enforce_constraint(constraint_id, ENFORCE_SCOPE)
                results.append((resource_type, reg_ok, enf_ok))
            else:
                results.append((resource_type, reg_ok, False))
            continue

        reg_ok = register_constraint(yaml_content, resource_type)

        if reg_ok:
            registered.append((resource_type, constraint_id, condition))

        if ENFORCE_TIMING == "immediate" and reg_ok:
            time.sleep(0 if DRY_RUN else 2)
            print(f"    Enforcing...")
            enf_ok = enforce_constraint(constraint_id, ENFORCE_SCOPE)
            results.append((resource_type, reg_ok, enf_ok))
        else:
            results.append((resource_type, reg_ok, False))

    # ── Phase 2: Enforce all at end ─────────────────────────
    if ENFORCE_TIMING == "end":
        print()
        print("─" * 56)
        print("  PHASE 2 — Enforcing all constraints")
        print("─" * 56)
        if not DRY_RUN:
            print("  Waiting 5s for propagation...")
            time.sleep(5)

        updated_results = []
        for resource_type, constraint_id, _ in registered:
            print(f"\n>>> Enforcing: {constraint_id}")
            enf_ok = enforce_constraint(constraint_id, ENFORCE_SCOPE)
            # update the result for this resource
            existing_result = next(
                (r for r in results if r[0] == resource_type), None
            )
            if existing_result:
                updated_results.append((resource_type, existing_result[1], enf_ok))
            else:
                updated_results.append((resource_type, False, enf_ok))

        # replace results with updated ones
        result_map = {r[0]: r for r in updated_results}
        results = [result_map.get(r[0], r) for r in results]

    print()
    print_summary(results)


if __name__ == "__main__":
    main()