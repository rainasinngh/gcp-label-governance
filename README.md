# gcp-label-governance

Automated label enforcement for GCP resources — blocks non-compliant creates where
possible, and cleans up what slips through where it isn't.

## Why two layers

GCP's custom org policy constraints (CEL-based) can enforce required labels at
**creation time** for some resource types — but not all. CEL only exposes label
fields for a subset of resource types (Compute, GKE, Storage), and only fires on
`CREATE`, not on a create-then-patch-labels pattern some IaC tools use. Resources
like BigQuery datasets, Cloud SQL instances, and Artifact Registry repos aren't
covered by org policy label enforcement at all.

So this repo has two layers:

1. **Preventive** (`register_constraints.py`) — org policy custom constraints,
   enforced at the organization level, for resource types CEL supports.
2. **Reactive** (`governance_service.py` + `setup_governance.py`) — a Cloud Run
   service triggered by audit-log events via Pub/Sub, for everything CEL can't
   cover (and as a backstop for #1). Deletes non-compliant resources shortly
   after creation and publishes an alert.

Layer 2 is a safety net, not a substitute for layer 1 — prefer blocking creation
over deleting after the fact wherever CEL supports it.

## Architecture

```
Resource created
      │
      ├─ CEL-supported type? ──► Org Policy Constraint ──► CREATE blocked if non-compliant
      │
      └─ Always ──► Cloud Audit Log
                          │
                          ▼
                    Log Sink (filtered by service+method)
                          │
                          ▼
                    Pub/Sub events topic
                          │
                          ▼
                    Push subscription ──► Cloud Run (governance_service.py)
                                                │
                                    ┌───────────┼────────────┐
                                    ▼           ▼             ▼
                              labels OK    labels missing   resource
                              → no-op      → delete         already gone
                                                │             → no-op
                                                ▼
                                        Pub/Sub alerts topic
```

## Resources covered

| Resource type | Blocked at creation (org policy) | Cleaned up if missed (Cloud Run) |
|---|:---:|:---:|
| Compute Instance (VM) | ✅ | ✅ |
| Persistent Disk | — | ✅ |
| Forwarding Rule | ✅ | ✅ |
| Instance Group Manager | ✅ | — |
| Storage Bucket | ✅ | — |
| GKE Cluster | ✅ | ✅ |
| BigQuery Dataset | — | ✅ |
| Cloud SQL Instance | — | ✅ |
| Artifact Registry Repo | — | ✅ |

**Known gap:** Cloud Functions and Cloud Run *services themselves* aren't
covered by either layer yet. See [Limitations](#limitations).

## Repo contents

```
register_constraints.py    # org policy custom constraints (run once / on label-policy change)
setup_governance.py        # idempotent infra setup for the Cloud Run backstop
governance_service.py      # the Cloud Run service itself
governance.config.json     # single source of config for setup + service
Dockerfile                 # Cloud Run build
requirements.txt           # Python deps
```

## Setup

### 1. Org policy constraints

```bash
python3 register_constraints.py --dry-run   # preview
python3 register_constraints.py             # apply
```

Edit `ORG_ID`, `REQUIRED_LABELS`, and `ENFORCE_SCOPE` at the top of the file first.

### 2. Cloud Run backstop

Fill in `governance.config.json`:

```jsonc
{
  "project_id": "your-project",
  "region": "us-central1",
  "governance": { "required_labels": ["owner", "env"] },
  "service_accounts": {
    "runtime": "governance-runtime@your-project.iam.gserviceaccount.com",
    "push_auth": "governance-push@your-project.iam.gserviceaccount.com"
  },
  "cloud_run": { "service_name": "governance-service" },
  "pubsub": {
    "events_topic": "governance-events",
    "alerts_topic": "governance-alerts",
    "push_subscription": "governance-events-push",
    "push_ack_deadline_seconds": 60,
    "dead_letter_topic": "governance-events-dlq",   // optional but recommended
    "max_delivery_attempts": 5                       // used only if dead_letter_topic is set
  },
  "logging": { "sink_name": "governance-audit-sink" }
}
```

```bash
python3 setup_governance.py --dry-run
python3 setup_governance.py --yes
```

This creates/updates (idempotently — safe to re-run): required APIs, Pub/Sub
topics, the log sink, the Cloud Run service, and the push subscription. It does
**not** create service accounts or IAM bindings — it prints a checklist of what
to grant manually at the end (see below).

To redeploy code changes without an env/config change: `--force-deploy`.

### 3. IAM (manual — run `setup_governance.py` once to get the exact principals)

- Log sink's writer identity → `roles/pubsub.publisher` on `events_topic`
- Push subscription's service account → `roles/run.invoker` on the Cloud Run service
- Google's Pub/Sub service agent → `roles/iam.serviceAccountTokenCreator` +
  `roles/iam.serviceAccountUser` on the push auth service account
- Runtime service account → per-resource-type get/delete roles (compute,
  storage, container, bigquery, cloudsql, artifactregistry admin-level roles)
  + `roles/pubsub.publisher` on `alerts_topic`
- If using a dead-letter topic: Pub/Sub service agent → `roles/pubsub.publisher`
  on the DLQ topic

## Testing a label policy change safely

Don't change `REQUIRED_LABELS` directly against production. The Cloud Run
service deletes non-compliant resources with no manual approval step — verify
the new label set against a non-production project first, and expect a short
propagation delay (org policy: 2–15 minutes) before constraints take effect.

## Limitations

- **CREATE-only enforcement.** A create-then-patch-labels pattern (some
  Terraform resources do this) is not accounted for — verify this matches how
  your IaC actually applies labels before rolling out broadly.
- **No orphan cleanup for cascade resources.** Deleting a `ForwardingRule`
  doesn't clean up its backend service, health check, or associated firewall
  rules. Deleting a GKE cluster doesn't clean up dynamically-provisioned PV
  disks or LoadBalancer Service resources created by workloads inside it —
  drain those first.
- **GKE-managed child resources aren't exempted.** A PD or ForwardingRule
  auto-created by a workload running inside a GKE cluster is tracked like any
  other resource of that type. If it doesn't carry your required labels, it
  can be deleted out from under a running, correctly-labeled cluster. Consider
  excluding resources carrying `goog-gke-*` labels before deploying real
  workloads into a governed cluster.
- **Single global label policy.** One `REQUIRED_LABELS` list for the whole
  org — no per-folder/per-environment label requirements yet.
- **Cloud Functions and Cloud Run services** are not covered by either layer.
- **Delete confirmation is fire-and-forget.** The Cloud Run service submits
  delete requests without blocking on completion (for latency — GKE cluster
  teardown alone can take minutes). An accepted request is treated as success;
  it does not guarantee the resource has actually finished being torn down.

## Local dev

```bash
pip install -r requirements.txt --break-system-packages
GOVERNANCE_CONFIG=./governance.config.json python3 -m flask --app governance_service run -p 8080
curl -X POST localhost:8080 -H 'Content-Type: application/json' -d '{"...": "..."}'
```

`governance_service.py` reads config from `GOVERNANCE_CONFIG` (or
`governance.config.json` next to the file), with `PROJECT_ID`, `ALERT_TOPIC`,
`REQUIRED_LABELS`, `GET_INSTANCE_MAX_ATTEMPTS`, and
`GET_INSTANCE_INITIAL_DELAY_SEC` env vars available as overrides.