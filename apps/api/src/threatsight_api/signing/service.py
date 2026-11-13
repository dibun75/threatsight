"""Signing requests, eligibility, verification, and bundles. No private keys here."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.readiness_models import (
    ReadinessAction,
    ReadinessAudit,
    ReadinessClosureRequirement,
    ReadinessEvidenceManifest,
)
from threatsight_api.persistence.signing_models import (
    EvidenceSignature,
    EvidenceSigningKey,
    EvidenceSigningPolicy,
    EvidenceSigningRequest,
)
from threatsight_api.signing import ALGORITHMS, DEFAULT_DEPLOYMENT_ID, SIGNATURE_SCHEMA
from threatsight_api.signing.envelope import build_envelope, canonical_json, digest_bytes
from threatsight_api.signing.provider import KeyProvider, verify_ed25519

ADMIN_ROLES = frozenset({"workspace-admin", "platform-admin", "admin"})
LEASE_SECONDS = 60
MAX_BUNDLE_BYTES = 256_000


def ensure_policy(db: Session, deployment_id: str = DEFAULT_DEPLOYMENT_ID) -> EvidenceSigningPolicy:
    row = db.scalar(select(EvidenceSigningPolicy).where(EvidenceSigningPolicy.deployment_id == deployment_id))
    if row is None:
        row = EvidenceSigningPolicy(deployment_id=deployment_id, kill_switch=False)
        db.add(row)
        db.flush()
    return row


def _audit(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    object_type: str,
    object_id: uuid.UUID,
    action: str,
    actor: str,
    payload: dict[str, Any],
) -> None:
    db.add(
        ReadinessAudit(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            object_type=object_type,
            object_id=object_id,
            action=action,
            actor=actor,
            payload=payload,
        )
    )


def _action(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, action_id: uuid.UUID) -> ReadinessAction:
    row = db.scalar(
        select(ReadinessAction).where(
            ReadinessAction.id == action_id,
            ReadinessAction.tenant_id == tenant_id,
            ReadinessAction.workspace_id == workspace_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    return row


def _manifest_for_action(db: Session, action: ReadinessAction) -> ReadinessEvidenceManifest | None:
    return db.scalar(
        select(ReadinessEvidenceManifest)
        .where(
            ReadinessEvidenceManifest.action_id == action.id,
            ReadinessEvidenceManifest.workspace_id == action.workspace_id,
        )
        .order_by(ReadinessEvidenceManifest.generated_at.desc())
    )


def _recompute_digest(manifest: ReadinessEvidenceManifest) -> str:
    body = json.loads(manifest.canonical_json)
    return digest_bytes(canonical_json(body))


def _mandatory_complete(db: Session, action: ReadinessAction) -> bool:
    rows = list(
        db.scalars(
            select(ReadinessClosureRequirement).where(
                ReadinessClosureRequirement.action_id == action.id,
                ReadinessClosureRequirement.workspace_id == action.workspace_id,
                ReadinessClosureRequirement.mandatory.is_(True),
            )
        )
    )
    return bool(rows) and all(row.status == "satisfied" for row in rows)


def _active_key(db: Session, deployment_id: str) -> EvidenceSigningKey | None:
    return db.scalar(
        select(EvidenceSigningKey).where(
            EvidenceSigningKey.deployment_id == deployment_id,
            EvidenceSigningKey.status == "active",
            EvidenceSigningKey.is_default.is_(True),
        )
    )


def eligibility(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    action_id: uuid.UUID,
    *,
    deployment_id: str = DEFAULT_DEPLOYMENT_ID,
) -> dict[str, Any]:
    action = _action(db, tenant_id, workspace_id, action_id)
    policy = ensure_policy(db, deployment_id)
    manifest = _manifest_for_action(db, action)
    reasons: list[str] = []
    if action.status != "closed":
        reasons.append("action_not_closed")
    if not _mandatory_complete(db, action):
        reasons.append("mandatory_requirements_incomplete")
    if not action.closed_by and not action.reviewer_subject:
        reasons.append("reviewer_missing")
    if manifest is None:
        reasons.append("manifest_missing")
    elif _recompute_digest(manifest) != manifest.digest:
        reasons.append("manifest_digest_mismatch")
    if policy.kill_switch:
        reasons.append("signing_kill_switch")
    key = _active_key(db, deployment_id)
    if key is None:
        reasons.append("active_key_unavailable")
    existing = None
    if manifest is not None:
        existing = db.scalar(
            select(EvidenceSignature).where(
                EvidenceSignature.manifest_id == manifest.id,
                EvidenceSignature.workspace_id == workspace_id,
            )
        )
        if existing is not None:
            reasons.append("signature_already_exists")
    eligible = not reasons
    return {
        "eligible": eligible,
        "reasons": reasons,
        "action_status": action.status,
        "manifest_id": None if manifest is None else str(manifest.id),
        "manifest_digest": None if manifest is None else manifest.digest,
        "active_key_id": None if key is None else key.key_id,
        "active_key_fingerprint": None if key is None else key.public_key_fingerprint,
        "kill_switch": policy.kill_switch,
        "label": "Unsigned" if existing is None else "Reference-signed evidence",
        "does_not_mean": "A deployment signature is not auditor approval, certification, or proof that a control works.",
    }


def request_signature(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    action_id: uuid.UUID,
    actor: str,
    role: str,
    *,
    idempotency_key: str,
    deployment_id: str = DEFAULT_DEPLOYMENT_ID,
) -> dict[str, Any]:
    if role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Administrator role required")
    if len(idempotency_key) < 8 or len(idempotency_key) > 200:
        raise HTTPException(status_code=422, detail="Invalid idempotency key")
    existing = db.scalar(
        select(EvidenceSigningRequest).where(
            EvidenceSigningRequest.workspace_id == workspace_id,
            EvidenceSigningRequest.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        return _request_out(existing)
    check = eligibility(db, tenant_id, workspace_id, action_id, deployment_id=deployment_id)
    if not check["eligible"]:
        raise HTTPException(status_code=409, detail={"code": "not_eligible", "reasons": check["reasons"]})
    action = _action(db, tenant_id, workspace_id, action_id)
    manifest = _manifest_for_action(db, action)
    assert manifest is not None
    row = EvidenceSigningRequest(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        action_id=action.id,
        manifest_id=manifest.id,
        expected_digest=manifest.digest,
        requested_by=actor,
        state="pending",
        idempotency_key=idempotency_key,
    )
    db.add(row)
    db.flush()
    _audit(
        db,
        tenant_id,
        workspace_id,
        "signing_request",
        row.id,
        "signing_requested",
        actor,
        {"manifest_id": str(manifest.id), "digest": manifest.digest},
    )
    return _request_out(row)


def claim_pending_request(db: Session, *, worker_id: str, deployment_id: str = DEFAULT_DEPLOYMENT_ID) -> EvidenceSigningRequest | None:
    policy = ensure_policy(db, deployment_id)
    if policy.kill_switch:
        return None
    now = datetime.now(UTC)
    row = db.scalar(
        select(EvidenceSigningRequest)
        .where(
            EvidenceSigningRequest.state == "pending",
            (EvidenceSigningRequest.lease_until.is_(None)) | (EvidenceSigningRequest.lease_until < now),
        )
        .order_by(EvidenceSigningRequest.created_at.asc())
        .with_for_update(skip_locked=True)
    )
    if row is None:
        return None
    row.lease_owner = worker_id
    row.lease_until = now + timedelta(seconds=LEASE_SECONDS)
    row.state = "leased"
    row.attempt_count += 1
    db.flush()
    _audit(
        db,
        row.tenant_id,
        row.workspace_id,
        "signing_request",
        row.id,
        "signing_leased",
        worker_id,
        {"attempt": row.attempt_count},
    )
    return row


def process_request(db: Session, request: EvidenceSigningRequest, provider: KeyProvider, *, deployment_id: str = DEFAULT_DEPLOYMENT_ID) -> EvidenceSignature:
    policy = ensure_policy(db, deployment_id)
    if policy.kill_switch:
        request.state = "failed"
        request.error_code = "signing_kill_switch"
        request.lease_owner = None
        request.lease_until = None
        db.flush()
        raise RuntimeError("signing_kill_switch")
    ok, reason = provider.ready()
    if not ok:
        request.state = "pending"
        request.error_code = reason
        request.lease_owner = None
        request.lease_until = None
        db.flush()
        raise RuntimeError(reason)
    material = provider.public_material()
    key = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == material.key_id))
    if key is None or key.status != "active" or key.deployment_id != deployment_id:
        request.state = "failed"
        request.error_code = "inactive_key"
        request.lease_owner = None
        request.lease_until = None
        db.flush()
        raise RuntimeError("inactive_key")
    action = db.get(ReadinessAction, request.action_id)
    manifest = db.get(ReadinessEvidenceManifest, request.manifest_id)
    if action is None or manifest is None:
        request.state = "failed"
        request.error_code = "missing_object"
        db.flush()
        raise RuntimeError("missing_object")
    if action.status != "closed":
        request.state = "failed"
        request.error_code = "action_not_closed"
        request.lease_owner = None
        request.lease_until = None
        db.flush()
        raise RuntimeError("action_not_closed")
    recomputed = _recompute_digest(manifest)
    if recomputed != manifest.digest or recomputed != request.expected_digest:
        request.state = "failed"
        request.error_code = "manifest_digest_mismatch"
        request.lease_owner = None
        request.lease_until = None
        db.flush()
        raise RuntimeError("manifest_digest_mismatch")
    prior = db.scalar(
        select(EvidenceSignature)
        .where(EvidenceSignature.action_id == action.id, EvidenceSignature.workspace_id == action.workspace_id)
        .order_by(EvidenceSignature.signed_at.desc())
    )
    signed_at = datetime.now(UTC)
    _envelope, canonical, envelope_digest = build_envelope(
        manifest_schema_version=manifest.schema_version,
        manifest_id=str(manifest.id),
        manifest_digest=manifest.digest,
        tenant_id=str(action.tenant_id),
        workspace_id=str(action.workspace_id),
        action_id=str(action.id),
        closure_outcome=action.closure_outcome,
        reviewer_subject=action.closed_by or action.reviewer_subject,
        signing_key_id=material.key_id,
        algorithm=material.algorithm,
        deployment_id=deployment_id,
        signed_at=signed_at,
        previous_signature_id=None if prior is None else str(prior.id),
    )
    signature = provider.sign(canonical.encode())
    row = EvidenceSignature(
        tenant_id=action.tenant_id,
        workspace_id=action.workspace_id,
        action_id=action.id,
        manifest_id=manifest.id,
        envelope_version=SIGNATURE_SCHEMA,
        canonical_envelope=canonical,
        envelope_digest=envelope_digest,
        signature_b64=base64.b64encode(signature).decode(),
        signing_key_id=material.key_id,
        algorithm=material.algorithm,
        deployment_id=deployment_id,
        signed_at=signed_at,
        verification_status_at_creation="valid_current",
        previous_signature_id=None if prior is None else prior.id,
        maturity="fixture_tested",
        label="Reference-signed evidence",
    )
    db.add(row)
    db.flush()
    request.state = "completed"
    request.signature_id = row.id
    request.completed_at = signed_at
    request.error_code = None
    request.lease_owner = None
    request.lease_until = None
    _audit(
        db,
        action.tenant_id,
        action.workspace_id,
        "evidence_signature",
        row.id,
        "signing_succeeded",
        request.requested_by,
        {"manifest_id": str(manifest.id), "key_id": material.key_id, "fingerprint": material.fingerprint},
    )
    db.flush()
    return row


def fail_request(db: Session, request: EvidenceSigningRequest, error_code: str, actor: str) -> None:
    request.state = "failed"
    request.error_code = error_code[:64]
    request.lease_owner = None
    request.lease_until = None
    _audit(
        db,
        request.tenant_id,
        request.workspace_id,
        "signing_request",
        request.id,
        "signing_failed",
        actor,
        {"error_code": error_code},
    )
    db.flush()


def verify_signature(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    signature_id: uuid.UUID,
    actor: str,
) -> dict[str, Any]:
    row = db.scalar(
        select(EvidenceSignature).where(
            EvidenceSignature.id == signature_id,
            EvidenceSignature.tenant_id == tenant_id,
            EvidenceSignature.workspace_id == workspace_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    key = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == row.signing_key_id))
    manifest = db.get(ReadinessEvidenceManifest, row.manifest_id)
    action = db.get(ReadinessAction, row.action_id)
    if key is None or manifest is None or action is None:
        raise HTTPException(status_code=404, detail="Not found")
    state = _verification_state(row, key, manifest, action)
    _audit(
        db,
        tenant_id,
        workspace_id,
        "evidence_signature",
        row.id,
        "signature_verified",
        actor,
        {"state": state},
    )
    return _signature_out(row, key, action, state=state)


def build_bundle(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    signature_id: uuid.UUID,
    actor: str,
) -> dict[str, Any]:
    detail = verify_signature(db, tenant_id, workspace_id, signature_id, actor)
    row = db.get(EvidenceSignature, signature_id)
    key = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == row.signing_key_id))  # type: ignore[union-attr]
    manifest = db.get(ReadinessEvidenceManifest, row.manifest_id)  # type: ignore[union-attr]
    assert row is not None and key is not None and manifest is not None
    bundle = {
        "bundle_schema_version": "threatsight.verification_bundle.v1",
        "limitations": [
            "Deployment signature of a finalized manifest digest only.",
            "Not auditor approval, certification, compliance, or control effectiveness.",
            "Reference-signed evidence when maturity is fixture_tested.",
        ],
        "verification_instructions": "Use threatsight-verify-evidence with this JSON. Offline. No private key required.",
        "manifest": {
            "id": str(manifest.id),
            "schema_version": manifest.schema_version,
            "digest": manifest.digest,
            "canonical_json": manifest.canonical_json,
        },
        "signature": {
            "id": str(row.id),
            "envelope_version": row.envelope_version,
            "canonical_envelope": row.canonical_envelope,
            "signature_b64": row.signature_b64,
            "algorithm": row.algorithm,
            "signing_key_id": row.signing_key_id,
            "deployment_id": row.deployment_id,
            "signed_at": row.signed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "label": row.label,
        },
        "public_key": {
            "key_id": key.key_id,
            "fingerprint": key.public_key_fingerprint,
            "algorithm": key.algorithm,
            "public_key_pem": key.public_key_pem,
            "status": key.status,
            "provider_type": key.provider_type,
        },
        "verification": detail,
    }
    encoded = json.dumps(bundle, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode()) > MAX_BUNDLE_BYTES:
        raise HTTPException(status_code=413, detail="Bundle too large")
    _audit(
        db,
        tenant_id,
        workspace_id,
        "evidence_signature",
        row.id,
        "bundle_downloaded",
        actor,
        {"bytes": len(encoded.encode())},
    )
    return {
        "filename": f"evidence-verification-{row.id}.json",
        "content_type": "application/json",
        "cache_control": "no-store",
        "bundle": bundle,
    }


def register_public_key(
    db: Session,
    *,
    key_id: str,
    deployment_id: str,
    public_key_pem: str,
    fingerprint: str,
    provider_type: str,
    maturity: str,
    actor: str,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
) -> EvidenceSigningKey:
    existing = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == key_id))
    if existing is not None:
        return existing
    row = EvidenceSigningKey(
        key_id=key_id,
        deployment_id=deployment_id,
        algorithm="Ed25519",
        public_key_pem=public_key_pem,
        public_key_fingerprint=fingerprint,
        provider_type=provider_type,
        status="pending",
        maturity=maturity,
        is_default=False,
        reason="operator_registered_public_metadata",
    )
    db.add(row)
    db.flush()
    _audit(
        db,
        tenant_id,
        workspace_id,
        "signing_key",
        row.id,
        "key_public_registered",
        actor,
        {"key_id": key_id, "fingerprint": fingerprint},
    )
    return row


def activate_key(
    db: Session,
    *,
    key_id: str,
    deployment_id: str,
    actor: str,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
) -> EvidenceSigningKey:
    row = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == key_id))
    if row is None or row.deployment_id != deployment_id:
        raise HTTPException(status_code=404, detail="Not found")
    if row.status == "revoked":
        raise HTTPException(status_code=409, detail="Revoked key cannot be activated")
    for other in db.scalars(
        select(EvidenceSigningKey).where(
            EvidenceSigningKey.deployment_id == deployment_id,
            EvidenceSigningKey.is_default.is_(True),
            EvidenceSigningKey.key_id != key_id,
        )
    ):
        if other.status == "active":
            other.status = "retired"
            other.is_default = False
            other.retired_at = datetime.now(UTC)
            _audit(
                db,
                tenant_id,
                workspace_id,
                "signing_key",
                other.id,
                "key_retired",
                actor,
                {"key_id": other.key_id},
            )
    row.status = "active"
    row.is_default = True
    row.activated_at = datetime.now(UTC)
    _audit(
        db,
        tenant_id,
        workspace_id,
        "signing_key",
        row.id,
        "key_activated",
        actor,
        {"key_id": key_id, "fingerprint": row.public_key_fingerprint},
    )
    db.flush()
    return row


def revoke_key(
    db: Session,
    *,
    key_id: str,
    actor: str,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    reason: str,
) -> EvidenceSigningKey:
    row = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == key_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    row.status = "revoked"
    row.is_default = False
    row.revoked_at = datetime.now(UTC)
    row.reason = reason[:500]
    _audit(
        db,
        tenant_id,
        workspace_id,
        "signing_key",
        row.id,
        "key_revoked",
        actor,
        {"key_id": key_id},
    )
    db.flush()
    return row


def set_kill_switch(
    db: Session,
    *,
    enabled: bool,
    actor: str,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    deployment_id: str = DEFAULT_DEPLOYMENT_ID,
) -> EvidenceSigningPolicy:
    policy = ensure_policy(db, deployment_id)
    policy.kill_switch = enabled
    _audit(
        db,
        tenant_id,
        workspace_id,
        "signing_policy",
        policy.id,
        "signing_kill_switch_changed",
        actor,
        {"kill_switch": enabled},
    )
    db.flush()
    return policy


def operational_health(db: Session, *, deployment_id: str = DEFAULT_DEPLOYMENT_ID, signer_ready: bool | None = None) -> dict[str, Any]:
    policy = ensure_policy(db, deployment_id)
    key = _active_key(db, deployment_id)
    pending = list(db.scalars(select(EvidenceSigningRequest).where(EvidenceSigningRequest.state.in_(("pending", "leased")))))
    failed = db.scalar(
        select(EvidenceSigningRequest).where(EvidenceSigningRequest.state == "failed").order_by(EvidenceSigningRequest.updated_at.desc())
    )
    last = db.scalar(select(EvidenceSignature).order_by(EvidenceSignature.signed_at.desc()))
    oldest = min((row.created_at for row in pending), default=None)
    oldest_age = None if oldest is None else int((datetime.now(UTC) - oldest.astimezone(UTC)).total_seconds())
    degraded = oldest_age is not None and oldest_age > policy.pending_degraded_seconds
    return {
        "signer": "unknown" if signer_ready is None else ("healthy" if signer_ready else "unhealthy"),
        "active_key_available": key is not None,
        "active_key_fingerprint": None if key is None else key.public_key_fingerprint,
        "pending_requests": len(pending),
        "failed_recent": failed is not None,
        "oldest_pending_age_seconds": oldest_age,
        "last_successful_signature_at": None if last is None else last.signed_at.isoformat(),
        "kill_switch": policy.kill_switch,
        "degraded": degraded,
        "does_not_include": "key_material_paths_or_secrets",
    }


def list_public_keys(db: Session, *, deployment_id: str = DEFAULT_DEPLOYMENT_ID) -> dict[str, Any]:
    rows = list(db.scalars(select(EvidenceSigningKey).where(EvidenceSigningKey.deployment_id == deployment_id)))
    return {
        "items": [
            {
                "key_id": row.key_id,
                "fingerprint": row.public_key_fingerprint,
                "algorithm": row.algorithm,
                "status": row.status,
                "provider_type": row.provider_type,
                "maturity": row.maturity,
                "is_default": row.is_default,
                "activated_at": None if row.activated_at is None else row.activated_at.isoformat(),
                "retired_at": None if row.retired_at is None else row.retired_at.isoformat(),
                "revoked_at": None if row.revoked_at is None else row.revoked_at.isoformat(),
            }
            for row in rows
        ]
    }


def signature_for_action(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, action_id: uuid.UUID) -> dict[str, Any] | None:
    action = _action(db, tenant_id, workspace_id, action_id)
    row = db.scalar(
        select(EvidenceSignature)
        .where(EvidenceSignature.action_id == action.id, EvidenceSignature.workspace_id == workspace_id)
        .order_by(EvidenceSignature.signed_at.desc())
    )
    if row is None:
        return None
    key = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == row.signing_key_id))
    if key is None:
        return None
    manifest = db.get(ReadinessEvidenceManifest, row.manifest_id)
    state = _verification_state(row, key, manifest, action) if manifest else "malformed_bundle"
    return _signature_out(row, key, action, state=state)


def _verification_state(
    signature: EvidenceSignature,
    key: EvidenceSigningKey,
    manifest: ReadinessEvidenceManifest,
    action: ReadinessAction,
) -> str:
    if signature.algorithm not in ALGORITHMS:
        return "unsupported_algorithm"
    if key.key_id != signature.signing_key_id:
        return "unknown_key"
    if _recompute_digest(manifest) != manifest.digest or manifest.digest != json.loads(signature.canonical_envelope).get("manifest_digest"):
        return "invalid_manifest_digest"
    try:
        sig = base64.b64decode(signature.signature_b64)
    except Exception:
        return "invalid_signature"
    if not verify_ed25519(public_key_pem=key.public_key_pem, message=signature.canonical_envelope.encode(), signature=sig):
        return "invalid_signature"
    if key.status == "revoked":
        return "valid_key_revoked_after_signing"
    if key.status == "retired":
        return "valid_key_retired"
    if action.status != "closed":
        return "valid_superseded"
    return "valid_current"


def _request_out(row: EvidenceSigningRequest) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "state": row.state,
        "manifest_id": str(row.manifest_id),
        "expected_digest": row.expected_digest,
        "attempt_count": row.attempt_count,
        "error_code": row.error_code,
        "signature_id": None if row.signature_id is None else str(row.signature_id),
        "completed_at": None if row.completed_at is None else row.completed_at.isoformat(),
    }


def _signature_out(row: EvidenceSignature, key: EvidenceSigningKey, action: ReadinessAction, *, state: str) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "label": row.label,
        "state": state,
        "manifest_id": str(row.manifest_id),
        "action_id": str(row.action_id),
        "action_status": action.status,
        "signing_key_id": row.signing_key_id,
        "fingerprint": key.public_key_fingerprint,
        "algorithm": row.algorithm,
        "deployment_id": row.deployment_id,
        "signed_at": row.signed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "maturity": row.maturity,
        "closure_current": action.status == "closed",
        "proves": "Deployment signed the finalized manifest digest with the identified key.",
        "does_not_prove": "Evidence factual correctness, control effectiveness, compliance, or auditor approval.",
    }
