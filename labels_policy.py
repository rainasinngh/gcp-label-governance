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
ORG_ID = "Enter ORG_ID her "

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

#Resource on which the org policy is to be enforced

RESOURCE_CONFIGS = [

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
    {
        "type": "compute.googleapis.com/ForwardingRule",
        "label_field": "resource.labels",
    },
    {
        "type": "compute.googleapis.com/InstanceGroupManager",
        "label_field": "resource.labels",
    },
]

#Build the CEL condition for the org policy

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

#Build the constraint id for the org policy

def build_constraint_id(resource_type: str) -> str:
    cleaned = resource_type.replace(".googleapis.com/", "/")
    parts = cleaned.split("/")
    suffix = "".join(part.capitalize() for part in parts)
    return f"custom.requireLabels{suffix}"

#Build the constraint yaml for the org policy

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
  Blocks creation of {resource_type} resources missing required
  labels: {labels_str}. New resources must have these label keys present
  and non-empty.
methodTypes:
  - CREATE
"""

#Run the command to execute the org policy

def run_command(cmd: list) -> tuple:
    print(f"    CMD: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True, result.stdout.strip()
    else:
        return False, result.stderr.strip()

#Checks if the constraint already exists

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

#Checks if the constraint needs to be updated

def constraint_needs_update(existing: dict, condition: str, resource_type: str) -> bool:
    if existing is None:
        return True

    existing_condition = existing.get("condition", "").strip()
    existing_resources = existing.get("resourceTypes", [])
    existing_methods = set(existing.get("methodTypes", []))

    condition_changed = existing_condition != condition.strip()
    resource_changed = resource_type not in existing_resources
    method_changed = existing_methods != {"CREATE"}

    if condition_changed:
        print(f"    Change detected: condition updated.")
    if resource_changed:
        print(f"    Change detected: resource type changed.")
    if method_changed:
        print(f"    Change detected: method types updated (CREATE only).")

    return condition_changed or resource_changed or method_changed

#Registers new  constraint

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

#Enforces the constraint via the policy

def enforce_constraint(constraint_id: str, scope: tuple) -> bool:
    """
    Enforces the constraint by writing a policy YAML and calling set-policy.
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

#Prints the header

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

#Confirms if the user wants to proceed , prompt the user for confirmation

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

#Prints the summary

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

#Main function to register the constraints and enforce them
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

#Builds the yaml content for the constraint
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

#Checks if the constraint already exists

        existing = get_existing_constraint(constraint_id, ORG_ID)

#Checks if the constraint needs to be updated , if not then skip the registration
#case 1: constraint already exists and no changes are needed , so move forward to enforce the constraint
#if the enforcement timing is immediate ,otherwise add the constraint to the results

       
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
#case2 : constraint does not exist or needs to be updated, so register the constraint and enforce it immediately if the enforcement timing is immediate
#otherwise add the constraint to the results
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
