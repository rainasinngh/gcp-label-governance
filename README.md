# gcp-label-governance
Two-layer GCP label governance: org policy constraints block non-compliant creates where CEL supports it; a Cloud Run service backstops the rest by deleting non-compliant resources on creation and alerting via Pub/Sub.
