#!/usr/bin/env python3
"""
Governance service — Cloud Run app (single file).

Receives create audit events via Pub/Sub push, checks required labels, deletes
non-compliant resources, and publishes alerts.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from flask import Flask, Request, jsonify, request
from google.api_core.exceptions import NotFound
from google.cloud import (
    artifactregistry_v1,
    bigquery,
    compute_v1,
    container_v1,
    pubsub_v1,
)
from googleapiclient import discovery
from googleapiclient.errors import HttpError

# ---------------------------------------------------------------------------
# Config — from governance.config.json (env vars override)
# ---------------------------------------------------------------------------
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "governance.config.json"


def _load_config() -> dict[str, Any]:
    path = Path(os.environ.get("GOVERNANCE_CONFIG", DEFAULT_CONFIG_PATH))
    if not path.is_file():
        raise FileNotFoundError(
            f"Config not found: {path}. Set GOVERNANCE_CONFIG or create governance.config.json"
        )
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _env_override(key: str, default: Any = None) -> Any:
    val = os.environ.get(key)
    return val if val not in (None, "") else default


_CFG = _load_config()
_GOV = _CFG.get("governance", {})
_PUBSUB = _CFG.get("pubsub", {})

PROJECT_ID = _env_override("PROJECT_ID") or _env_override("GOOGLE_CLOUD_PROJECT") or _CFG.get("project_id")
if not PROJECT_ID:
    raise ValueError("project_id must be set in config or PROJECT_ID env var")

ALERT_TOPIC = _env_override("ALERT_TOPIC", _PUBSUB.get("alerts_topic"))
if not ALERT_TOPIC:
    raise ValueError("alerts_topic must be set in config or ALERT_TOPIC env var")

_labels_raw = _env_override("REQUIRED_LABELS")
if _labels_raw:
    REQUIRED_LABELS = tuple(l.strip() for l in str(_labels_raw).split(",") if l.strip())
else:
    REQUIRED_LABELS = tuple(_GOV.get("required_labels", []))
if not REQUIRED_LABELS:
    raise ValueError("required_labels must be set in config or REQUIRED_LABELS env var")

GET_MAX_ATTEMPTS = int(_env_override("GET_INSTANCE_MAX_ATTEMPTS", _GOV.get("get_max_attempts", 5)))
GET_INITIAL_DELAY_SEC = float(
    _env_override("GET_INSTANCE_INITIAL_DELAY_SEC", _GOV.get("get_initial_delay_seconds", 1.0))
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource registry
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ResourceSpec:
    key: str
    resource_type: str
    service_name: str
    method_names: frozenset[str]
    pattern: re.Pattern[str]


RESOURCE_SPECS: tuple[ResourceSpec, ...] = (
    ResourceSpec(
        "vm", "compute.googleapis.com/Instance", "compute.googleapis.com",
        frozenset({"v1.compute.instances.insert", "beta.compute.instances.insert"}),
        re.compile(r"^projects/(?P<project>[^/]+)/zones/(?P<zone>[^/]+)/instances/(?P<name>[^/]+)$"),
    ),
    ResourceSpec(
        "disk", "compute.googleapis.com/Disk", "compute.googleapis.com",
        frozenset({"v1.compute.disks.insert", "beta.compute.disks.insert"}),
        re.compile(r"^projects/(?P<project>[^/]+)/zones/(?P<zone>[^/]+)/disks/(?P<name>[^/]+)$"),
    ),
    ResourceSpec(
        "forwarding_rule", "compute.googleapis.com/ForwardingRule", "compute.googleapis.com",
        frozenset({"v1.compute.forwardingRules.insert", "beta.compute.forwardingRules.insert"}),
        re.compile(r"^projects/(?P<project>[^/]+)/regions/(?P<region>[^/]+)/forwardingRules/(?P<name>[^/]+)$"),
    ),
    ResourceSpec(
        "gke_cluster", "container.googleapis.com/Cluster", "container.googleapis.com",
        frozenset({"google.container.v1.ClusterManager.CreateCluster", "CreateCluster"}),
        re.compile(r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/clusters/(?P<name>[^/]+)$"),
    ),
    ResourceSpec(
        "bigquery_dataset", "bigquery.googleapis.com/Dataset", "bigquery.googleapis.com",
        frozenset({
            "datasets.insert",
            "google.cloud.bigquery.v2.DatasetService.InsertDataset",
        }),
        re.compile(r"^projects/(?P<project>[^/]+)/datasets/(?P<name>[^/]+)$"),
    ),
    ResourceSpec(
        "cloud_sql", "sqladmin.googleapis.com/Instance", "cloudsql.googleapis.com",
        frozenset({"cloudsql.instances.create", "v1.sql.instances.insert"}),
        re.compile(r"^projects/(?P<project>[^/]+)/instances/(?P<name>[^/]+)$"),
    ),
    ResourceSpec(
        "artifact_registry", "artifactregistry.googleapis.com/Repository", "artifactregistry.googleapis.com",
        frozenset({
            "google.devtools.artifactregistry.v1.ArtifactRegistry.CreateRepository",
            "CreateRepository",
        }),
        re.compile(r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/repositories/(?P<name>[^/]+)$"),
    ),
)

_METHOD_TO_SPEC = {m: s for s in RESOURCE_SPECS for m in s.method_names}


@dataclass(frozen=True)
class ResourceCreateEvent:
    resource_key: str
    resource_type: str
    project: str
    name: str
    creator: str
    method_name: str
    resource_name: str
    zone: str | None = None
    region: str | None = None
    location: str | None = None


# ---------------------------------------------------------------------------
# Audit log parsing
# ---------------------------------------------------------------------------
def _resolve_creator(payload: dict[str, Any]) -> str:
    auth = payload.get("authenticationInfo", {})
    if not isinstance(auth, dict):
        return "unknown"
    for key in ("principalEmail", "principalSubject", "serviceAccountKeyName"):
        if auth.get(key):
            return str(auth[key])
    return "unknown"


_BQ_DATASET_PATH = re.compile(r"^projects/(?P<project>[^/]+)/datasets/(?P<name>[^/]+)$")


def _resolve_bq_dataset(payload: dict[str, Any], log_entry: dict[str, Any]) -> tuple[str, str] | None:
    resource_name = str(payload.get("resourceName", ""))
    match = _BQ_DATASET_PATH.match(resource_name)
    if match:
        return match.group("project"), match.group("name")

    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        creation = metadata.get("datasetCreation")
        if isinstance(creation, dict):
            dataset = creation.get("dataset")
            if isinstance(dataset, dict):
                full_name = dataset.get("datasetName", "")
                if isinstance(full_name, str):
                    nested = _BQ_DATASET_PATH.match(full_name)
                    if nested:
                        return nested.group("project"), nested.group("name")

    service_data = payload.get("serviceData")
    if isinstance(service_data, dict):
        insert_req = service_data.get("datasetInsertRequest")
        if isinstance(insert_req, dict):
            resource = insert_req.get("resource")
            if isinstance(resource, dict):
                ds_name = resource.get("datasetName")
                if isinstance(ds_name, dict) and ds_name.get("datasetId"):
                    project = str(ds_name.get("projectId") or "")
                    if not project:
                        resource_meta = log_entry.get("resource")
                        if isinstance(resource_meta, dict):
                            labels = resource_meta.get("labels")
                            if isinstance(labels, dict):
                                project = str(labels.get("project_id") or "")
                    if project:
                        return project, str(ds_name["datasetId"])

    resource_meta = log_entry.get("resource")
    if isinstance(resource_meta, dict):
        labels = resource_meta.get("labels")
        if isinstance(labels, dict) and labels.get("dataset_id") and labels.get("project_id"):
            return str(labels["project_id"]), str(labels["dataset_id"])
    return None


def parse_resource_create_event(log_entry: dict[str, Any]) -> ResourceCreateEvent | None:
    payload = log_entry.get("protoPayload")
    if not isinstance(payload, dict):
        return None
    spec = _METHOD_TO_SPEC.get(payload.get("methodName", ""))
    if spec is None or payload.get("serviceName") != spec.service_name:
        return None

    if spec.key == "bigquery_dataset":
        resolved = _resolve_bq_dataset(payload, log_entry)
        if not resolved:
            return None
        project, name = resolved
        resource_name = f"projects/{project}/datasets/{name}"
        return ResourceCreateEvent(
            resource_key=spec.key,
            resource_type=spec.resource_type,
            project=project,
            name=name,
            creator=_resolve_creator(payload),
            method_name=payload.get("methodName", ""),
            resource_name=resource_name,
        )

    resource_name = payload.get("resourceName", "")
    match = spec.pattern.match(resource_name)
    if not match:
        return None
    g = match.groupdict()
    return ResourceCreateEvent(
        resource_key=spec.key,
        resource_type=spec.resource_type,
        project=g["project"],
        name=g["name"],
        creator=_resolve_creator(payload),
        method_name=payload.get("methodName", ""),
        resource_name=resource_name,
        zone=g.get("zone"),
        region=g.get("region"),
        location=g.get("location"),
    )


def _unwrap_body(body: Any) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None
    if "protoPayload" in body:
        return body
    data = body.get("data")
    if isinstance(data, dict):
        return _unwrap_body(data)
    if isinstance(data, str):
        for decoder in (
            lambda v: json.loads(base64.b64decode(v).decode()),
            json.loads,
        ):
            try:
                parsed = decoder(data)
                if isinstance(parsed, dict):
                    nested = _unwrap_body(parsed)
                    if nested:
                        return nested
            except (json.JSONDecodeError, UnicodeDecodeError, binascii.Error):
                continue
    message = body.get("message")
    if isinstance(message, dict) and "data" in message:
        try:
            parsed = json.loads(base64.b64decode(message["data"]).decode())
            if isinstance(parsed, dict):
                return _unwrap_body(parsed)
        except (json.JSONDecodeError, UnicodeDecodeError, binascii.Error):
            pass
    return None


def parse_audit_log_entry(req: Request) -> dict[str, Any] | None:
    body = req.get_json(silent=True)
    if body is None:
        raw = req.get_data(as_text=True)
        if not raw:
            return None
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            return None
    return _unwrap_body(body)


# ---------------------------------------------------------------------------
# Retry + label check + alerts
# ---------------------------------------------------------------------------
def _retry_get(operation: Callable[[], Any], resource_desc: str) -> Any | None:
    delay = GET_INITIAL_DELAY_SEC
    for attempt in range(1, GET_MAX_ATTEMPTS + 1):
        try:
            return operation()
        except NotFound:
            if attempt == GET_MAX_ATTEMPTS:
                logger.warning("%s not found after %s attempts", resource_desc, GET_MAX_ATTEMPTS)
                return None
            time.sleep(delay)
            delay *= 2
    return None


def _missing_labels(labels: dict[str, str]) -> list[str]:
    return [k for k in REQUIRED_LABELS if not str(labels.get(k, "")).strip()]


_publisher: pubsub_v1.PublisherClient | None = None


def _publish_alert(event: ResourceCreateEvent, missing: list[str]) -> None:
    global _publisher
    if _publisher is None:
        _publisher = pubsub_v1.PublisherClient()
    topic = _publisher.topic_path(PROJECT_ID, ALERT_TOPIC)
    msg = {
        "action": "resource_deleted",
        "resource_type": event.resource_type,
        "resource_name": event.resource_name,
        "project": event.project,
        "resource": event.name,
        "created_by": event.creator,
        "reason": "missing_required_labels",
        "missing_labels": missing,
    }
    _publisher.publish(topic, json.dumps(msg, indent=2).encode()).result(timeout=30)


# ---------------------------------------------------------------------------
# GCP API helpers (lazy clients — no credentials needed at import)
# ---------------------------------------------------------------------------
_clients: dict[str, Any] = {}


def _client(name: str, factory: Callable[[], Any]) -> Any:
    if name not in _clients:
        _clients[name] = factory()
    return _clients[name]


def _get_vm_labels(e: ResourceCreateEvent) -> dict[str, str] | None:
    instances = _client("compute_instances", compute_v1.InstancesClient)
    vm = _retry_get(
        lambda: instances.get(project=e.project, zone=e.zone, instance=e.name),
        e.resource_name,
    )
    return dict(vm.labels or {}) if vm else None


def _delete_vm(e: ResourceCreateEvent) -> bool:
    instances = _client("compute_instances", compute_v1.InstancesClient)
    try:
        instances.delete(project=e.project, zone=e.zone, instance=e.name).result(timeout=300)
        return True
    except NotFound:
        return True
    except Exception:
        logger.exception("delete vm failed: %s", e.resource_name)
        return False


def _get_disk_labels(e: ResourceCreateEvent) -> dict[str, str] | None:
    disks = _client("compute_disks", compute_v1.DisksClient)
    disk = _retry_get(
        lambda: disks.get(project=e.project, zone=e.zone, disk=e.name),
        e.resource_name,
    )
    return dict(disk.labels or {}) if disk else None


def _delete_disk(e: ResourceCreateEvent) -> bool:
    disks = _client("compute_disks", compute_v1.DisksClient)
    try:
        disks.delete(project=e.project, zone=e.zone, disk=e.name).result(timeout=300)
        return True
    except NotFound:
        return True
    except Exception:
        logger.exception("delete disk failed: %s", e.resource_name)
        return False


def _get_rule_labels(e: ResourceCreateEvent) -> dict[str, str] | None:
    rules = _client("compute_rules", compute_v1.ForwardingRulesClient)
    rule = _retry_get(
        lambda: rules.get(project=e.project, region=e.region, forwarding_rule=e.name),
        e.resource_name,
    )
    return dict(rule.labels or {}) if rule else None


def _delete_rule(e: ResourceCreateEvent) -> bool:
    rules = _client("compute_rules", compute_v1.ForwardingRulesClient)
    try:
        rules.delete(project=e.project, region=e.region, forwarding_rule=e.name).result(timeout=300)
        return True
    except NotFound:
        return True
    except Exception:
        logger.exception("delete forwarding rule failed: %s", e.resource_name)
        return False


def _get_gke_labels(e: ResourceCreateEvent) -> dict[str, str] | None:
    gke = _client("gke", container_v1.ClusterManagerClient)
    cluster = _retry_get(
        lambda: gke.get_cluster(project_id=e.project, zone=e.location, cluster_id=e.name),
        e.resource_name,
    )
    return dict(cluster.resource_labels or {}) if cluster else None


def _delete_gke(e: ResourceCreateEvent) -> bool:
    gke = _client("gke", container_v1.ClusterManagerClient)
    try:
        gke.delete_cluster(project_id=e.project, zone=e.location, cluster_id=e.name).result(timeout=900)
        return True
    except NotFound:
        return True
    except Exception:
        logger.exception("delete gke failed: %s", e.resource_name)
        return False


def _bq(project: str) -> bigquery.Client:
    return _client(f"bq_{project}", lambda: bigquery.Client(project=project))


def _get_bq_labels(e: ResourceCreateEvent) -> dict[str, str] | None:
    ds = _retry_get(lambda: _bq(e.project).get_dataset(e.name), e.resource_name)
    return dict(ds.labels or {}) if ds else None


def _delete_bq(e: ResourceCreateEvent) -> bool:
    try:
        _bq(e.project).delete_dataset(e.name, delete_contents=True, not_found_ok=True)
        return True
    except Exception:
        logger.exception("delete dataset failed: %s", e.resource_name)
        return False


def _get_sql_labels(e: ResourceCreateEvent) -> dict[str, str] | None:
    sqladmin = _client("sqladmin", lambda: discovery.build("sqladmin", "v1", cache_discovery=False))

    def fetch() -> dict:
        try:
            return sqladmin.instances().get(project=e.project, instance=e.name).execute()
        except HttpError as exc:
            if exc.resp.status == 404:
                raise NotFound(e.resource_name) from exc
            raise

    resp = _retry_get(fetch, e.resource_name)
    return dict((resp or {}).get("settings", {}).get("userLabels") or {})


def _delete_sql(e: ResourceCreateEvent) -> bool:
    sqladmin = _client("sqladmin", lambda: discovery.build("sqladmin", "v1", cache_discovery=False))
    try:
        sqladmin.instances().delete(project=e.project, instance=e.name).execute()
        return True
    except HttpError as exc:
        if exc.resp.status == 404:
            return True
        logger.exception("delete sql failed: %s", e.resource_name)
        return False
    except Exception:
        logger.exception("delete sql failed: %s", e.resource_name)
        return False


def _get_ar_labels(e: ResourceCreateEvent) -> dict[str, str] | None:
    artifact = _client("artifact", artifactregistry_v1.ArtifactRegistryClient)
    path = f"projects/{e.project}/locations/{e.location}/repositories/{e.name}"
    repo = _retry_get(lambda: artifact.get_repository(name=path), e.resource_name)
    return dict(repo.labels or {}) if repo else None


def _delete_ar(e: ResourceCreateEvent) -> bool:
    artifact = _client("artifact", artifactregistry_v1.ArtifactRegistryClient)
    path = f"projects/{e.project}/locations/{e.location}/repositories/{e.name}"
    try:
        artifact.delete_repository(name=path).result(timeout=300)
        return True
    except NotFound:
        return True
    except Exception:
        logger.exception("delete repo failed: %s", e.resource_name)
        return False


HANDLERS: dict[str, tuple[Callable, Callable]] = {
    "vm": (_get_vm_labels, _delete_vm),
    "disk": (_get_disk_labels, _delete_disk),
    "forwarding_rule": (_get_rule_labels, _delete_rule),
    "gke_cluster": (_get_gke_labels, _delete_gke),
    "bigquery_dataset": (_get_bq_labels, _delete_bq),
    "cloud_sql": (_get_sql_labels, _delete_sql),
    "artifact_registry": (_get_ar_labels, _delete_ar),
}


def handle_create(event: ResourceCreateEvent) -> dict[str, Any]:
    get_labels, delete_fn = HANDLERS[event.resource_key]
    labels = get_labels(event)
    if labels is None:
        return {"status": "ignored", "reason": "resource_not_found", "resource": event.name}

    missing = _missing_labels(labels)
    if not missing:
        return {"status": "compliant", "resource_type": event.resource_type, "resource": event.name}

    logger.warning("Non-compliant %s missing=%s", event.resource_name, missing)
    if not delete_fn(event):
        return {"status": "error", "reason": "delete_failed", "missing_labels": missing}

    alert_status = "published"
    try:
        _publish_alert(event, missing)
    except Exception:
        logger.exception("alert publish failed for %s", event.resource_name)
        alert_status = "failed"

    return {
        "status": "deleted",
        "resource_type": event.resource_type,
        "resource": event.name,
        "missing_labels": missing,
        "creator": event.creator,
        "alert_status": alert_status,
    }


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/", methods=["POST"])
def handle_event():
    log_entry = parse_audit_log_entry(request)
    if log_entry is None:
        return jsonify({"status": "ignored", "reason": "invalid_payload"}), 200

    event = parse_resource_create_event(log_entry)
    if event is None:
        method = log_entry.get("protoPayload", {}).get("methodName")
        logger.info("Ignoring unsupported create: %s", method)
        return jsonify({"status": "ignored", "reason": "unsupported_create"}), 200

    logger.info("Processing %s: %s", event.resource_type, event.resource_name)
    try:
        result = handle_create(event)
    except Exception:
        logger.exception("Processing failed: %s", event.resource_name)
        return jsonify({"error": "processing_failed"}), 500
    return jsonify(result), 200
