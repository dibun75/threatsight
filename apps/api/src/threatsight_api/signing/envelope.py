"""Canonical signature envelope helpers."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from threatsight_api.signing import SIGNATURE_SCHEMA


def canonical_json(body: dict[str, Any]) -> str:
    return json.dumps(body, separators=(",", ":"), sort_keys=True)


def digest_bytes(canonical: str) -> str:
    return hashlib.sha256(canonical.encode()).hexdigest()


def build_envelope(
    *,
    manifest_schema_version: str,
    manifest_id: str,
    manifest_digest: str,
    tenant_id: str,
    workspace_id: str,
    action_id: str,
    closure_outcome: str | None,
    reviewer_subject: str | None,
    signing_key_id: str,
    algorithm: str,
    deployment_id: str,
    signed_at: datetime,
    previous_signature_id: str | None,
) -> tuple[dict[str, Any], str, str]:
    body = {
        "schema_version": SIGNATURE_SCHEMA,
        "manifest_schema_version": manifest_schema_version,
        "manifest_id": manifest_id,
        "manifest_digest": manifest_digest,
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "action_id": action_id,
        "closure_outcome": closure_outcome,
        "reviewer_subject": reviewer_subject,
        "signing_key_id": signing_key_id,
        "algorithm": algorithm,
        "deployment_id": deployment_id,
        "signed_at": signed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "previous_signature_id": previous_signature_id,
        "proves": [
            "deployment_signed_manifest_digest",
            "signing_key_identity",
            "envelope_integrity",
            "signed_at_timestamp",
        ],
        "does_not_prove": [
            "evidence_factual_correctness",
            "control_effectiveness",
            "remediation_success",
            "organizational_security",
            "auditor_approval",
            "legal_non_repudiation",
            "regulatory_compliance",
            "certification",
        ],
    }
    canonical = canonical_json(body)
    return body, canonical, digest_bytes(canonical)
