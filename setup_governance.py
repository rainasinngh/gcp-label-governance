#!/usr/bin/env python3
"""
Setup script — idempotent governance infrastructure (no SA/IAM creation).

For each resource:
  - missing  → create
  - exists + changed → update
  - exists + unchanged → skip

Reads settings from governance.config.json.

Usage:
    python3 setup_governance.py --yes
    python3 setup_governance.py --dry-run
    python3 setup_governance.py --force-deploy --yes   # redeploy Cloud Run even if env unchanged
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

DEFAULT_CONFIG = Path(__file__).resolve().parent / "governance.config.json"

APIS = [
    "run.googleapis.com",
    "pubsub.googleapis.com",
    "logging.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "bigquery.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
]

AUDIT_FILTERS = [
    {
        "service_name": "compute.googleapis.com",
        "method_names": [
            "v1.compute.instances.insert",
            "beta.compute.instances.insert",
            "v1.compute.disks.insert",
            "beta.compute.disks.insert",
            "v1.compute.forwardingRules.insert",
            "beta.compute.forwardingRules.insert",
        ],
    },
    {
        "service_name": "bigquery.googleapis.com",
        "method_names": [
            "datasets.insert",
            "google.cloud.bigquery.v2.DatasetService.InsertDataset",
        ],
    },
    {
        "service_name": "container.googleapis.com",
        "method_names": [
            "google.container.v1.ClusterManager.CreateCluster",
            "CreateCluster",
        ],
    },
    {
        "service_name": "cloudsql.googleapis.com",
        "method_names": ["cloudsql.instances.create", "v1.sql.instances.insert"],
    },
    {
        "service_name": "artifactregistry.googleapis.com",
        "method_names": [
            "google.devtools.artifactregistry.v1.ArtifactRegistry.CreateRepository",
            "CreateRepository",
        ],
    },
]


def load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Config not found: {path}")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _require(cfg: dict, *keys: str) -> Any:
    cur = cfg
    for key in keys:
        if key not in cur or cur[key] in (None, "", []):
            raise ValueError(f"Missing config: {'.'.join(keys)}")
        cur = cur[key]
    return cur


def build_log_filter(audit_filters: list[dict]) -> str:
    parts = []
    for block in audit_filters:
        methods = " OR ".join(
            f'protoPayload.methodName="{m}"' for m in block["method_names"]
        )
        parts.append(
            f'(protoPayload.serviceName="{block["service_name"]}" AND ({methods}))'
        )
    return " OR ".join(parts)


def _normalize_filter(expr: str) -> str:
    return re.sub(r"\s+", " ", expr.strip())


def gcloud(project_id: str, args: list[str], *, dry_run: bool, mutate: bool = True) -> tuple[bool, str]:
    cmd = ["gcloud", "--project", project_id, *args]
    print(f"  $ {' '.join(cmd)}")
    if dry_run and mutate:
        return True, ""
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout or r.stderr or "").strip()
    if r.returncode == 0:
        return True, r.stdout.strip()
    print(f"  ERROR: {out}")
    return False, out


def gcloud_json(project_id: str, args: list[str], *, dry_run: bool) -> dict | None:
    ok, out = gcloud(project_id, args + ["--format=json"], dry_run=dry_run, mutate=False)
    if not ok or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def describe(project_id: str, args: list[str], *, dry_run: bool) -> dict | None:
    return gcloud_json(project_id, args, dry_run=dry_run)


def desired_cloud_run_env(cfg: dict) -> dict[str, str]:
    return {
        "PROJECT_ID": cfg["project_id"],
        "ALERT_TOPIC": cfg["pubsub"]["alerts_topic"],
        "REQUIRED_LABELS": ",".join(cfg["governance"]["required_labels"]),
        "GOVERNANCE_CONFIG": "/app/governance.config.json",
    }


def sync_apis(project_id: str, *, dry_run: bool) -> bool:
    print("\n[apis]")
    ok, _ = gcloud(project_id, ["services", "enable", *APIS], dry_run=dry_run)
    print("  enabled (idempotent)" if ok else "  failed")
    return ok


def sync_topic(project_id: str, name: str, *, dry_run: bool) -> bool:
    print(f"\n[topic] {name}")
    if describe(project_id, ["pubsub", "topics", "describe", name], dry_run=dry_run):
        print("  skip (exists)")
        return True
    ok, _ = gcloud(project_id, ["pubsub", "topics", "create", name], dry_run=dry_run)
    print("  created" if ok and not dry_run else "  would create")
    return ok


def sync_sink(cfg: dict, *, dry_run: bool) -> tuple[bool, str | None]:
    project_id = cfg["project_id"]
    sink_name = cfg["logging"]["sink_name"]
    events_topic = cfg["pubsub"]["events_topic"]
    dest = f"pubsub.googleapis.com/projects/{project_id}/topics/{events_topic}"
    desired_filter = build_log_filter(AUDIT_FILTERS)

    print(f"\n[sink] {sink_name}")
    data = describe(project_id, ["logging", "sinks", "describe", sink_name], dry_run=dry_run)

    if data is None:
        ok, _ = gcloud(
            project_id,
            ["logging", "sinks", "create", sink_name, dest, f"--log-filter={desired_filter}"],
            dry_run=dry_run,
        )
        if not ok:
            return False, None
        print("  created" if not dry_run else "  would create")
        data = describe(project_id, ["logging", "sinks", "describe", sink_name], dry_run=dry_run)
        return True, (data or {}).get("writerIdentity")

    writer = data.get("writerIdentity")
    current_filter = _normalize_filter(data.get("filter", ""))
    current_dest = data.get("destination", "")

    if current_filter == _normalize_filter(desired_filter) and current_dest == dest:
        print(f"  skip (unchanged), writer={writer}")
        return True, writer

    ok, _ = gcloud(
        project_id,
        ["logging", "sinks", "update", sink_name, f"--log-filter={desired_filter}"],
        dry_run=dry_run,
    )
    if not ok:
        return False, writer
    print("  updated filter" if not dry_run else "  would update filter")
    return True, writer


def _current_cloud_run_env(data: dict) -> dict[str, str]:
    containers = data.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    if not containers:
        return {}
    env_list = containers[0].get("env", []) or []
    return {item["name"]: str(item.get("value", "")) for item in env_list if "name" in item}


def sync_cloud_run(
    cfg: dict,
    source_dir: Path,
    *,
    dry_run: bool,
    force_deploy: bool,
) -> tuple[bool, str | None]:
    project_id = cfg["project_id"]
    region = cfg["region"]
    service_name = cfg["cloud_run"]["service_name"]
    runtime_sa = cfg["service_accounts"]["runtime"]
    desired_env = desired_cloud_run_env(cfg)
    env_vars = (
        f"^:^PROJECT_ID={desired_env['PROJECT_ID']}:"
        f"ALERT_TOPIC={desired_env['ALERT_TOPIC']}:"
        f"REQUIRED_LABELS={desired_env['REQUIRED_LABELS']}:"
        f"GOVERNANCE_CONFIG={desired_env['GOVERNANCE_CONFIG']}"
    )

    print(f"\n[cloud run] {service_name} ({region})")
    data = describe(
        project_id, ["run", "services", "describe", service_name, "--region", region], dry_run=dry_run
    )

    if data and not force_deploy:
        current_sa = (
            data.get("spec", {}).get("template", {}).get("spec", {}).get("serviceAccountName", "")
        )
        current_env = _current_cloud_run_env(data)
        if current_sa == runtime_sa and current_env == desired_env:
            url = data.get("status", {}).get("url")
            print(f"  skip (config unchanged), url={url}")
            print("  tip: use --force-deploy to push code changes")
            return True, url

    if dry_run:
        print(f"  would deploy from {source_dir}")
        url = (data or {}).get("status", {}).get("url")
        return True, url or f"https://{service_name}-example.{region}.run.app"

    ok, _ = gcloud(
        project_id,
        [
            "run", "deploy", service_name,
            "--source", str(source_dir),
            "--region", region,
            "--service-account", runtime_sa,
            "--set-env-vars", env_vars,
            "--no-allow-unauthenticated",
            "--quiet",
        ],
        dry_run=dry_run,
    )
    if not ok:
        return False, None

    data = describe(
        project_id, ["run", "services", "describe", service_name, "--region", region], dry_run=dry_run
    )
    url = (data or {}).get("status", {}).get("url")
    print(f"  deployed: {url}")
    return True, url


def sync_push_sub(cfg: dict, service_url: str, *, dry_run: bool) -> bool:
    project_id = cfg["project_id"]
    pubsub = cfg["pubsub"]
    accounts = cfg["service_accounts"]
    push_sa = accounts.get("push_auth") or accounts["runtime"]

    subscription = pubsub["push_subscription"]
    events_topic = pubsub["events_topic"]
    ack = int(pubsub.get("push_ack_deadline_seconds", 60))
    desired_endpoint = service_url.rstrip("/") + "/"

    print(f"\n[push sub] {subscription}")
    data = describe(project_id, ["pubsub", "subscriptions", "describe", subscription], dry_run=dry_run)

    update_args = [
        f"--push-endpoint={desired_endpoint}",
        f"--push-auth-service-account={push_sa}",
        f"--ack-deadline={ack}",
    ]

    if data:
        push_cfg = data.get("pushConfig", {}) or {}
        current_endpoint = push_cfg.get("pushEndpoint", "")
        current_ack = int(data.get("ackDeadlineSeconds", 0))
        current_topic = data.get("topic", "")
        oidc = push_cfg.get("oidcToken", {}) or {}
        current_sa = oidc.get("serviceAccountEmail", "")

        if (
            current_endpoint == desired_endpoint
            and current_sa == push_sa
            and current_ack == ack
            and current_topic.endswith(f"/topics/{events_topic}")
        ):
            print("  skip (unchanged)")
            return True

        ok, _ = gcloud(
            project_id, ["pubsub", "subscriptions", "update", subscription, *update_args], dry_run=dry_run
        )
        print("  updated" if ok and not dry_run else "  would update")
        return ok

    ok, _ = gcloud(
        project_id,
        ["pubsub", "subscriptions", "create", subscription, f"--topic={events_topic}", *update_args],
        dry_run=dry_run,
    )
    print("  created" if ok and not dry_run else "  would create")
    return ok


def print_iam_checklist(cfg: dict, sink_writer: str | None, service_url: str | None, *, dry_run: bool) -> None:
    project_id = cfg["project_id"]
    pubsub = cfg["pubsub"]
    accounts = cfg["service_accounts"]
    push_sa = accounts.get("push_auth") or accounts["runtime"]
    service_name = cfg["cloud_run"]["service_name"]
    region = cfg["region"]

    data = gcloud_json(project_id, ["projects", "describe", project_id], dry_run=dry_run)
    num = (data or {}).get("projectNumber", "<PROJECT_NUMBER>")
    pubsub_agent = f"service-{num}@gcp-sa-pubsub.iam.gserviceaccount.com"

    print("\n" + "=" * 60)
    print("MANUAL IAM (not applied by this script)")
    print("=" * 60)
    print(f"\n1. Sink writer → topic {pubsub['events_topic']}")
    print(f"   {sink_writer or '<sink writer>'}  →  roles/pubsub.publisher")
    print(f"\n2. Push SA → Cloud Run")
    print(f"   {push_sa}  →  roles/run.invoker on {service_name}")
    print(f"\n3. Pub/Sub agent → push SA")
    print(f"   {pubsub_agent}  →  tokenCreator + serviceAccountUser on {push_sa}")
    print(f"\n4. Runtime SA → APIs + alerts")
    print(f"   {accounts['runtime']}")
    print("   roles/compute.instanceAdmin.v1  (or compute.admin) — VM get/delete")
    print("   roles/compute.storageAdmin — disk get/delete")
    print("   roles/compute.networkAdmin — forwarding rule get/delete")
    print("   roles/container.clusterAdmin — GKE get/delete")
    print("   roles/bigquery.dataOwner — dataset get/delete")
    print("   roles/cloudsql.admin — Cloud SQL get/delete")
    print("   roles/artifactregistry.admin — repo get/delete")
    print("     (repoAdmin does NOT include artifactregistry.repositories.delete)")
    print(f"   roles/pubsub.publisher on topic {pubsub['alerts_topic']}")
    if service_url:
        print(f"\nCloud Run URL: {service_url}")
    print(f"Region: {region}")
    print("=" * 60)


def validate_config(cfg: dict) -> None:
    _require(cfg, "project_id")
    _require(cfg, "region")
    _require(cfg, "governance", "required_labels")
    _require(cfg, "service_accounts", "runtime")
    _require(cfg, "cloud_run", "service_name")
    _require(cfg, "pubsub", "events_topic")
    _require(cfg, "pubsub", "alerts_topic")
    _require(cfg, "pubsub", "push_subscription")
    _require(cfg, "logging", "sink_name")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Idempotent governance infra: create / update / skip per resource"
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", "-y", action="store_true")
    parser.add_argument(
        "--force-deploy",
        action="store_true",
        help="Redeploy Cloud Run even when env/service-account config is unchanged",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    validate_config(cfg)
    source_dir = args.config.resolve().parent

    print("Governance setup (idempotent)")
    print(f"  config  = {args.config}")
    print(f"  project = {cfg['project_id']}  region = {cfg['region']}")
    print(f"  labels  = {cfg['governance']['required_labels']}")
    print(f"  service = {cfg['cloud_run']['service_name']}")

    if not args.dry_run and not args.yes:
        if input("\nContinue? (yes/no): ").strip().lower() != "yes":
            print("Aborted.")
            return 0

    project_id = cfg["project_id"]
    results: dict[str, bool] = {}

    results["apis"] = sync_apis(project_id, dry_run=args.dry_run)
    results["events_topic"] = sync_topic(project_id, cfg["pubsub"]["events_topic"], dry_run=args.dry_run)
    results["alerts_topic"] = sync_topic(project_id, cfg["pubsub"]["alerts_topic"], dry_run=args.dry_run)

    sink_ok, writer = sync_sink(cfg, dry_run=args.dry_run)
    results["sink"] = sink_ok

    run_ok, url = sync_cloud_run(
        cfg, source_dir, dry_run=args.dry_run, force_deploy=args.force_deploy
    )
    results["cloud_run"] = run_ok

    results["push_sub"] = sync_push_sub(cfg, url, dry_run=args.dry_run) if run_ok and url else False

    print("\nResults:")
    for k, v in results.items():
        print(f"  {k:<16} {'OK' if v else 'FAIL'}")

    print_iam_checklist(cfg, writer, url, dry_run=args.dry_run)
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
