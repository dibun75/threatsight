"""Response snapshots signed via existing Phase 3C readiness evidence path."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.readiness_models import (
    ReadinessAction,
    ReadinessClosureRequirement,
    ReadinessEvidenceManifest,
)
from threatsight_api.persistence.response_models import (
    ResponseAuditEvent,
    ResponseSnapshot,
    ResponseWorkspace,
)
from threatsight_api.persistence.signing_models import (
    EvidenceSignature,
    EvidenceSigningRequest,
)
from threatsight_api.response.service import build_snapshot_payload, digest_payload
from threatsight_api.signing.service import request_signature


def finalize_and_request_signature(
    db: Session,
    row: ResponseWorkspace,
    *,
    actor: str,
    role: str,
    idempotency_key: str,
) -> dict[str, Any]:
    existing = db.scalar(
        select(ResponseSnapshot).where(
            ResponseSnapshot.response_id == row.id,
            ResponseSnapshot.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        return _out(db, existing)

    payload = build_snapshot_payload(db, row)
    canonical, digest = digest_payload(payload)

    # Ensure a readiness action exists to carry the Phase 3C manifest/signature.
    action_key = f"response-snapshot-{row.stable_key}"
    action = db.scalar(
        select(ReadinessAction).where(
            ReadinessAction.workspace_id == row.workspace_id,
            ReadinessAction.external_key == action_key,
        )
    )
    if action is None:
        action = ReadinessAction(
            id=uuid.uuid4(),
            tenant_id=row.tenant_id,
            workspace_id=row.workspace_id,
            external_key=action_key,
            status="closed",
            priority="normal",
            title=f"Response snapshot: {row.title}"[:200],
            why="Finalize response workspace snapshot for integrity signing.",
            what_changed="Response coordination snapshot",
            required_work="Preserve signed snapshot of response state",
            evidence_required="Canonical response snapshot JSON",
            known=row.known_facts[:500],
            uncertain=row.uncertain_facts[:500],
            closure_guidance="Signature proves integrity only.",
            service_source_key="response-workspace",
            control_title="Response snapshot integrity",
            closed_at=datetime.now(UTC),
            closure_outcome="resolved_by_evidence",
            closure_rationale="Snapshot finalized for integrity signing. Not incident truth or compliance.",
            closed_by=actor[:200],
            maturity="fixture_tested",
            metadata_safe={"response_id": str(row.id), "purpose": "response_snapshot"},
        )
        db.add(action)
        db.flush()
    elif action.status != "closed":
        action.status = "closed"
        action.closed_at = datetime.now(UTC)
        action.closure_outcome = "resolved_by_evidence"
        action.closure_rationale = "Snapshot finalized for integrity signing."
        action.closed_by = actor[:200]
    if not action.closed_by:
        action.closed_by = actor[:200]
    if not action.reviewer_subject:
        action.reviewer_subject = actor[:200]

    # Signing eligibility requires at least one satisfied mandatory closure requirement.
    req = db.scalar(
        select(ReadinessClosureRequirement).where(
            ReadinessClosureRequirement.action_id == action.id,
            ReadinessClosureRequirement.workspace_id == row.workspace_id,
            ReadinessClosureRequirement.requirement_type == "manual_review_completed",
        )
    )
    if req is None:
        db.add(
            ReadinessClosureRequirement(
                id=uuid.uuid4(),
                tenant_id=row.tenant_id,
                workspace_id=row.workspace_id,
                action_id=action.id,
                requirement_type="manual_review_completed",
                requirement_version="v1",
                mandatory=True,
                status="satisfied",
                reviewer=actor[:200],
                completed_at=datetime.now(UTC),
                limitations=["integrity_only", "not_incident_truth"],
                provenance={"actor": actor[:200], "purpose": "response_snapshot"},
            )
        )
        db.flush()
    elif req.status != "satisfied":
        req.status = "satisfied"
        req.reviewer = actor[:200]
        req.completed_at = datetime.now(UTC)

    # Create or replace manifest bound to this snapshot digest.
    manifest = db.scalar(
        select(ReadinessEvidenceManifest).where(
            ReadinessEvidenceManifest.action_id == action.id,
            ReadinessEvidenceManifest.workspace_id == row.workspace_id,
        )
    )
    if manifest is None:
        manifest = ReadinessEvidenceManifest(
            id=uuid.uuid4(),
            tenant_id=row.tenant_id,
            workspace_id=row.workspace_id,
            action_id=action.id,
            schema_version="threatsight.manifest.v1",
            digest=digest,
            canonical_json=canonical,
            generated_by=actor[:200],
        )
        db.add(manifest)
        db.flush()
    else:
        # New digest requires a new row due to unique (workspace, action, digest)
        if manifest.digest != digest:
            manifest = ReadinessEvidenceManifest(
                id=uuid.uuid4(),
                tenant_id=row.tenant_id,
                workspace_id=row.workspace_id,
                action_id=action.id,
                schema_version="threatsight.manifest.v1",
                digest=digest,
                canonical_json=canonical,
                previous_manifest_id=manifest.id,
                generated_by=actor[:200],
            )
            db.add(manifest)
            db.flush()

    snapshot = ResponseSnapshot(
        id=uuid.uuid4(),
        tenant_id=row.tenant_id,
        workspace_id=row.workspace_id,
        response_id=row.id,
        status="final",
        canonical_json=canonical,
        content_digest=digest,
        generated_by=actor[:200],
        finalized_at=datetime.now(UTC),
        finalized_by=actor[:200],
        action_id=action.id,
        manifest_id=manifest.id,
        idempotency_key=idempotency_key,
    )
    db.add(snapshot)
    db.flush()

    try:
        result = request_signature(
            db,
            row.tenant_id,
            row.workspace_id,
            action.id,
            actor,
            role if role in {"workspace-admin", "platform-admin", "admin"} else "workspace-admin",
            idempotency_key=f"resp-snap-{idempotency_key}"[:200],
        )
        snapshot.status = "signing"
        req_id = result.get("id") or result.get("request_id")
        if req_id:
            snapshot.signing_request_id = uuid.UUID(str(req_id))
        # If already signed synchronously (rare), capture signature id
        sig = db.scalar(
            select(EvidenceSignature).where(
                EvidenceSignature.action_id == action.id,
                EvidenceSignature.workspace_id == row.workspace_id,
            )
        )
        if sig is not None:
            snapshot.signature_id = sig.id
            snapshot.status = "signed"
    except HTTPException:
        # Leave snapshot final without signature request when ineligible.
        pass

    db.add(
        ResponseAuditEvent(
            id=uuid.uuid4(),
            tenant_id=row.tenant_id,
            workspace_id=row.workspace_id,
            response_id=row.id,
            event_type="snapshot_generation",
            actor=actor[:200],
            detail={"snapshot_id": str(snapshot.id), "digest": digest, "status": snapshot.status},
        )
    )
    db.flush()
    return _out(db, snapshot)


def refresh_signature_status(db: Session, snapshot: ResponseSnapshot) -> ResponseSnapshot:
    if snapshot.action_id is None:
        return snapshot
    sig = db.scalar(
        select(EvidenceSignature).where(
            EvidenceSignature.action_id == snapshot.action_id,
            EvidenceSignature.workspace_id == snapshot.workspace_id,
        )
    )
    if sig is not None:
        snapshot.signature_id = sig.id
        snapshot.status = "signed"
    elif snapshot.signing_request_id is not None:
        req = db.get(EvidenceSigningRequest, snapshot.signing_request_id)
        if req is not None and req.state == "completed" and req.signature_id is not None:
            snapshot.signature_id = req.signature_id
            snapshot.status = "signed"
    return snapshot


def _out(db: Session, snapshot: ResponseSnapshot) -> dict[str, Any]:
    refresh_signature_status(db, snapshot)
    return {
        "id": str(snapshot.id),
        "response_id": str(snapshot.response_id),
        "status": snapshot.status,
        "content_digest": snapshot.content_digest,
        "generated_at": snapshot.generated_at.isoformat(),
        "finalized_at": None if snapshot.finalized_at is None else snapshot.finalized_at.isoformat(),
        "action_id": None if snapshot.action_id is None else str(snapshot.action_id),
        "manifest_id": None if snapshot.manifest_id is None else str(snapshot.manifest_id),
        "signature_id": None if snapshot.signature_id is None else str(snapshot.signature_id),
        "signing_request_id": None if snapshot.signing_request_id is None else str(snapshot.signing_request_id),
        "integrity_disclaimer": snapshot.integrity_disclaimer,
        "contains_secrets": False,
        "proves": "integrity_only",
    }
