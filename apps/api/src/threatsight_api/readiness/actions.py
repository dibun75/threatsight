"""Accountable readiness-action lifecycle, ownership, closure, and manifests."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import Identity, WorkspaceMembership
from threatsight_api.persistence.readiness_models import (
    ReadinessAction,
    ReadinessActionAssignment,
    ReadinessAudit,
    ReadinessClosureRequirement,
    ReadinessDecision,
    ReadinessEvidenceLink,
    ReadinessEvidenceManifest,
    ReadinessRecommendation,
    ReadinessResult,
    ReadinessVerificationRequest,
)
from threatsight_api.presentation import public_name
from threatsight_api.readiness.vocabulary import APPROVE_ROLES, REVIEW_ROLES

ACTION_STATES = {
    "open",
    "assigned",
    "in_progress",
    "awaiting_evidence",
    "ready_for_review",
    "closed",
    "reopened",
    "superseded",
    "cancelled",
}
CLOSURE_OUTCOMES = {
    "resolved_by_evidence",
    "remediation_completed",
    "not_applicable",
    "risk_accepted",
    "superseded",
}
PRIORITIES = {"low", "normal", "high", "urgent"}
REQUIREMENT_TYPES = {
    "evidence_item_attached",
    "defined_verification_completed",
    "installed_version_recorded",
    "configuration_reviewed",
    "control_owner_confirmed",
    "exception_risk_acceptance_documented",
    "not_applicable_rationale_reviewed",
    "manual_review_completed",
}
TRANSITIONS: dict[str, set[str]] = {
    "open": {"assigned", "cancelled", "superseded"},
    "assigned": {"open", "in_progress", "awaiting_evidence", "cancelled", "superseded"},
    "in_progress": {"awaiting_evidence", "ready_for_review", "cancelled", "superseded"},
    "awaiting_evidence": {"in_progress", "ready_for_review", "cancelled", "superseded"},
    "ready_for_review": {"awaiting_evidence", "closed", "cancelled", "superseded"},
    "closed": {"reopened", "superseded"},
    "reopened": {"assigned", "in_progress", "awaiting_evidence", "cancelled", "superseded"},
    "superseded": set(),
    "cancelled": set(),
}
MANIFEST_SCHEMA = "threatsight.manifest.v1"
MAX_RISK_ACCEPTANCE_DAYS = 90
_NOT_FOUND = "Readiness object not found"


def summary(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID) -> dict:
    rows = list(
        db.scalars(
            select(ReadinessAction).where(
                ReadinessAction.tenant_id == tenant_id,
                ReadinessAction.workspace_id == workspace_id,
                ReadinessAction.status.notin_(("superseded", "cancelled")),
            )
        )
    )
    now = datetime.now(UTC)
    return {
        "unassigned": sum(1 for row in rows if row.owner_identity_id is None and row.status in {"open", "reopened"}),
        "due_soon": sum(1 for row in rows if row.due_at and now <= row.due_at <= now + timedelta(days=7) and row.status not in {"closed", "cancelled", "superseded"}),
        "overdue": sum(1 for row in rows if row.due_at and row.due_at < now and row.status not in {"closed", "cancelled", "superseded"}),
        "awaiting_evidence": sum(1 for row in rows if row.status == "awaiting_evidence"),
        "ready_for_review": sum(1 for row in rows if row.status == "ready_for_review"),
        "reopened": sum(1 for row in rows if row.status == "reopened"),
        "does_not_mean": "An action summary is not a risk score, SLA, or compliance result.",
    }


def list_actions(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    *,
    status: str | None = None,
    service: str | None = None,
    owner: str | None = None,
    due: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    stmt = select(ReadinessAction).where(
        ReadinessAction.tenant_id == tenant_id,
        ReadinessAction.workspace_id == workspace_id,
    )
    if status:
        stmt = stmt.where(ReadinessAction.status == status)
    if service:
        stmt = stmt.where(ReadinessAction.service_source_key == service)
    if owner == "unassigned":
        stmt = stmt.where(ReadinessAction.owner_identity_id.is_(None))
    elif owner:
        stmt = stmt.where(ReadinessAction.owner_subject == owner)
    rows = list(db.scalars(stmt.order_by(ReadinessAction.updated_at.desc()).offset(offset).limit(limit)))
    now = datetime.now(UTC)
    if due == "overdue":
        rows = [row for row in rows if row.due_at and row.due_at < now and row.status not in {"closed", "cancelled", "superseded"}]
    elif due == "due_soon":
        rows = [row for row in rows if row.due_at and now <= row.due_at <= now + timedelta(days=7)]
    return {"items": [_action_out(db, row) for row in rows], "count": len(rows)}


def get_action(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, action_id: uuid.UUID) -> dict:
    return _action_out(db, _action(db, tenant_id, workspace_id, action_id), detail=True)


def ensure_action_for_decision(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    decision: ReadinessDecision,
    *,
    actor: str,
) -> ReadinessAction:
    request = db.get(ReadinessVerificationRequest, decision.request_id)
    if request is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    recommendation = db.get(ReadinessRecommendation, request.recommendation_id)
    result = db.get(ReadinessResult, decision.result_id) if decision.result_id else None
    external_key = f"action:{request.id}"
    existing = db.scalar(
        select(ReadinessAction).where(
            ReadinessAction.workspace_id == workspace_id,
            ReadinessAction.external_key == external_key,
        )
    )
    if existing is not None:
        return existing
    evidence = db.scalar(
        select(ReadinessEvidenceLink).where(
            ReadinessEvidenceLink.request_id == request.id,
            ReadinessEvidenceLink.workspace_id == workspace_id,
        )
    )
    action = ReadinessAction(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        external_key=external_key,
        status="open",
        priority="normal",
        title=(recommendation.control_title if recommendation else "Readiness verification follow-up")[:200],
        why=(recommendation.rationale if recommendation else "A readiness decision requires accountable follow-up.")[:2000],
        what_changed="A verification result was recorded and a human decision was taken.",
        required_work="Assign an owner, satisfy closure requirements, and complete an authorized review.",
        evidence_required="Attached verification evidence and a completed mandatory checklist.",
        known="A defined check produced a normalized result. Maturity remains reference-validated.",
        uncertain="Control effectiveness, live exposure, and commercial ownership remain unknown.",
        closure_guidance="Closure requires mandatory requirements, an authorized reviewer, and an explicit outcome.",
        service_source_key=recommendation.service_source_key if recommendation else "unknown",
        service_node_id=None if recommendation is None else recommendation.service_node_id,
        control_title=recommendation.control_title if recommendation else "Unspecified control",
        trigger_id=None if recommendation is None else recommendation.trigger_id,
        recommendation_id=None if recommendation is None else recommendation.id,
        request_id=request.id,
        result_id=None if result is None else result.id,
        decision_id=decision.id,
        evidence_id=None if evidence is None else evidence.evidence_id,
        snapshot_id=None if recommendation is None else None,
        maturity="fixture_tested",
        metadata_safe={"created_from": "decision"},
    )
    db.add(action)
    db.flush()
    _seed_requirements(db, action, recommendation.check_id if recommendation else "synthetic.version.validate.v1")
    _audit(db, tenant_id, workspace_id, "action", action.id, "created", actor, {"decision_id": str(decision.id)})
    return action


def assign(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    action_id: uuid.UUID,
    owner_identity_id: uuid.UUID | None,
    actor: str,
    role: str,
    *,
    due_at: datetime | None = None,
    expected_version: int | None = None,
) -> dict:
    _require_write(role)
    action = _action(db, tenant_id, workspace_id, action_id)
    _expect_version(action, expected_version)
    if action.status in {"closed", "cancelled", "superseded"}:
        raise HTTPException(status_code=409, detail="Action cannot be assigned in its current state")
    if owner_identity_id is None:
        action.owner_identity_id = None
        action.owner_subject = None
        action.assigned_by = actor
        action.assigned_at = datetime.now(UTC)
        if action.status == "assigned":
            action.status = "open"
        note = "unassigned"
    else:
        identity, subject = _active_member(db, workspace_id, owner_identity_id)
        action.owner_identity_id = identity.id
        action.owner_subject = subject
        action.assigned_by = actor
        action.assigned_at = datetime.now(UTC)
        if action.status in {"open", "reopened"}:
            action.status = "assigned"
        note = "assigned"
    if due_at is not None:
        action.due_at = due_at.astimezone(UTC)
    action.version += 1
    db.add(
        ReadinessActionAssignment(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            action_id=action.id,
            owner_identity_id=action.owner_identity_id,
            owner_subject=action.owner_subject,
            assigned_by=actor,
            note=note,
        )
    )
    _audit(db, tenant_id, workspace_id, "action", action.id, note, actor, {"owner_subject": action.owner_subject})
    db.flush()
    return _action_out(db, action, detail=True)


def transition(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    action_id: uuid.UUID,
    target: str,
    actor: str,
    role: str,
    *,
    rationale: str = "",
    expected_version: int | None = None,
) -> dict:
    _require_write(role)
    if target not in ACTION_STATES:
        raise HTTPException(status_code=400, detail="Unsupported action status")
    action = _action(db, tenant_id, workspace_id, action_id)
    _expect_version(action, expected_version)
    allowed = TRANSITIONS.get(action.status, set())
    if target not in allowed:
        raise HTTPException(status_code=409, detail=f"Transition {action.status} → {target} is not permitted")
    if target == "closed":
        raise HTTPException(status_code=409, detail="Use the review-and-close endpoint to close an action")
    if target in {"cancelled", "superseded"} and role not in APPROVE_ROLES:
        raise HTTPException(status_code=403, detail="Administrator permission required")
    previous = action.status
    action.status = target
    if target == "cancelled":
        action.closure_rationale = (rationale or "Cancelled")[:1000]
        action.closed_by = actor
        action.closed_at = datetime.now(UTC)
    action.version += 1
    _audit(db, tenant_id, workspace_id, "action", action.id, "transition", actor, {"from": previous, "to": target})
    db.flush()
    return _action_out(db, action, detail=True)


def satisfy_requirement(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    action_id: uuid.UUID,
    requirement_id: uuid.UUID,
    actor: str,
    role: str,
    *,
    evidence_id: uuid.UUID | None = None,
) -> dict:
    _require_write(role)
    action = _action(db, tenant_id, workspace_id, action_id)
    requirement = db.scalar(
        select(ReadinessClosureRequirement).where(
            ReadinessClosureRequirement.id == requirement_id,
            ReadinessClosureRequirement.action_id == action.id,
            ReadinessClosureRequirement.workspace_id == workspace_id,
        )
    )
    if requirement is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    if evidence_id is not None:
        link = db.scalar(
            select(ReadinessEvidenceLink).where(
                ReadinessEvidenceLink.evidence_id == evidence_id,
                ReadinessEvidenceLink.workspace_id == workspace_id,
            )
        )
        if link is None and action.evidence_id != evidence_id:
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        from threatsight_api.persistence.models import EvidenceRecord

        evidence = db.get(EvidenceRecord, evidence_id)
        if evidence is None:
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        requirement.evidence_id = evidence.id
        requirement.evidence_hash = evidence.integrity_hash
    elif action.evidence_id is not None:
        from threatsight_api.persistence.models import EvidenceRecord

        evidence = db.get(EvidenceRecord, action.evidence_id)
        if evidence is not None:
            requirement.evidence_id = evidence.id
            requirement.evidence_hash = evidence.integrity_hash
    requirement.status = "satisfied"
    requirement.reviewer = actor
    requirement.completed_at = datetime.now(UTC)
    if action.status in {"assigned", "in_progress", "open", "reopened"}:
        action.status = "awaiting_evidence"
    if _mandatory_complete(db, action):
        action.status = "ready_for_review"
    action.version += 1
    _audit(db, tenant_id, workspace_id, "action", action.id, "requirement_satisfied", actor, {"requirement": requirement.requirement_type})
    db.flush()
    return _action_out(db, action, detail=True)


def close(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    action_id: uuid.UUID,
    outcome: str,
    rationale: str,
    actor: str,
    role: str,
    *,
    expected_version: int | None = None,
    risk_accepted_until: datetime | None = None,
    risk_scope: str | None = None,
) -> dict:
    if role not in APPROVE_ROLES:
        raise HTTPException(status_code=403, detail="Administrator review required to close")
    if outcome not in CLOSURE_OUTCOMES:
        raise HTTPException(status_code=400, detail="Unsupported closure outcome")
    action = _action(db, tenant_id, workspace_id, action_id)
    _expect_version(action, expected_version)
    if action.status != "ready_for_review":
        raise HTTPException(status_code=409, detail="Action must be ready for review before closure")
    if not _mandatory_complete(db, action):
        raise HTTPException(status_code=409, detail="Mandatory closure requirements are incomplete")
    if outcome == "risk_accepted":
        if risk_accepted_until is None:
            raise HTTPException(status_code=400, detail="Risk acceptance requires an expiry date")
        until = risk_accepted_until.astimezone(UTC)
        if until > datetime.now(UTC) + timedelta(days=MAX_RISK_ACCEPTANCE_DAYS):
            raise HTTPException(status_code=400, detail="Risk-acceptance expiry exceeds the 90-day cap")
        action.risk_accepted_until = until
        action.risk_review_at = until
        action.risk_scope = (risk_scope or "scoped reference acceptance")[:500]
    hashes = _evidence_hashes(db, action)
    action.status = "closed"
    action.closure_outcome = outcome
    action.closure_rationale = rationale[:1000]
    action.closed_by = actor
    action.closed_at = datetime.now(UTC)
    action.reviewer_subject = actor
    action.evidence_hash_at_closure = hashlib.sha256("|".join(hashes).encode()).hexdigest() if hashes else None
    action.version += 1
    manifest = _build_manifest(db, action, actor)
    _audit(db, tenant_id, workspace_id, "action", action.id, "closed", actor, {"outcome": outcome, "digest": manifest.digest})
    db.flush()
    return _action_out(db, action, detail=True)


def reopen(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    action_id: uuid.UUID,
    reason: str,
    actor: str,
    role: str,
    *,
    expected_version: int | None = None,
    new_evidence_hash: str | None = None,
) -> dict:
    if role not in APPROVE_ROLES and role not in REVIEW_ROLES:
        raise HTTPException(status_code=403, detail="Review permission required")
    action = _action(db, tenant_id, workspace_id, action_id)
    _expect_version(action, expected_version)
    if action.status != "closed":
        raise HTTPException(status_code=409, detail="Only closed actions can be reopened")
    previous_outcome = action.closure_outcome
    previous_hash = action.evidence_hash_at_closure
    action.status = "reopened"
    action.reopen_reason = reason[:500]
    action.closure_outcome = None
    action.closed_at = None
    action.closed_by = None
    action.version += 1
    _audit(
        db,
        tenant_id,
        workspace_id,
        "action",
        action.id,
        "reopened",
        actor,
        {
            "reason": reason[:200],
            "previous_outcome": previous_outcome,
            "previous_hash": previous_hash,
            "new_hash": new_evidence_hash,
        },
    )
    db.flush()
    return _action_out(db, action, detail=True)


def preview_manifest(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, action_id: uuid.UUID) -> dict:
    action = _action(db, tenant_id, workspace_id, action_id)
    body, digest = _manifest_body(db, action)
    return {
        "schema_version": MANIFEST_SCHEMA,
        "digest": digest,
        "label": "Evidence manifest",
        "integrity_digest": digest,
        "is_signed": False,
        "does_not_mean": "An integrity digest is not a digital signature, attestation, or certification.",
        "preview": body,
    }


def download_manifest(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, action_id: uuid.UUID, actor: str) -> dict:
    action = _action(db, tenant_id, workspace_id, action_id)
    row = db.scalar(
        select(ReadinessEvidenceManifest)
        .where(ReadinessEvidenceManifest.action_id == action.id, ReadinessEvidenceManifest.workspace_id == workspace_id)
        .order_by(ReadinessEvidenceManifest.generated_at.desc())
    )
    if row is None:
        if action.status != "closed":
            raise HTTPException(status_code=409, detail="Generate a manifest after closure")
        row = _build_manifest(db, action, actor)
        db.flush()
    _audit(db, tenant_id, workspace_id, "action", action.id, "manifest_downloaded", actor, {"digest": row.digest})
    return {
        "filename": f"evidence-manifest-{action.id}.json",
        "content_type": "application/json",
        "cache_control": "no-store",
        "digest": row.digest,
        "canonical_json": row.canonical_json,
        "label": "Evidence manifest",
        "is_signed": False,
    }


def due_state(action: ReadinessAction, *, now: datetime | None = None) -> str | None:
    if action.due_at is None or action.status in {"closed", "cancelled", "superseded"}:
        return None
    current = now or datetime.now(UTC)
    if action.due_at < current:
        return "overdue"
    if action.due_at <= current + timedelta(days=7):
        return "due_soon"
    return "scheduled"


def _seed_requirements(db: Session, action: ReadinessAction, check_id: str) -> None:
    types = ["defined_verification_completed", "manual_review_completed"]
    if "version" in check_id or "synthetic.version" in check_id:
        types.insert(0, "installed_version_recorded")
    if "privileged" in check_id:
        types = ["defined_verification_completed", "control_owner_confirmed", "manual_review_completed"]
    if "junos" in check_id:
        types = ["configuration_reviewed", "installed_version_recorded", "manual_review_completed"]
    for requirement_type in types:
        db.add(
            ReadinessClosureRequirement(
                tenant_id=action.tenant_id,
                workspace_id=action.workspace_id,
                action_id=action.id,
                requirement_type=requirement_type,
                mandatory=True,
                limitations=["synthetic_reference", "not_control_effectiveness"],
                provenance={"check_id": check_id},
            )
        )
    db.flush()


def _build_manifest(db: Session, action: ReadinessAction, actor: str) -> ReadinessEvidenceManifest:
    previous = db.scalar(
        select(ReadinessEvidenceManifest)
        .where(ReadinessEvidenceManifest.action_id == action.id)
        .order_by(ReadinessEvidenceManifest.generated_at.desc())
    )
    body, digest = _manifest_body(db, action, previous_id=None if previous is None else str(previous.id))
    row = ReadinessEvidenceManifest(
        tenant_id=action.tenant_id,
        workspace_id=action.workspace_id,
        action_id=action.id,
        schema_version=MANIFEST_SCHEMA,
        digest=digest,
        canonical_json=json.dumps(body, separators=(",", ":"), sort_keys=True),
        previous_manifest_id=None if previous is None else previous.id,
        generated_by=actor,
    )
    db.add(row)
    _audit(db, action.tenant_id, action.workspace_id, "action", action.id, "manifest_generated", actor, {"digest": digest})
    return row


def _manifest_body(db: Session, action: ReadinessAction, previous_id: str | None = None) -> tuple[dict, str]:
    requirements = list(
        db.scalars(
            select(ReadinessClosureRequirement).where(
                ReadinessClosureRequirement.action_id == action.id,
                ReadinessClosureRequirement.workspace_id == action.workspace_id,
            )
        )
    )
    body = {
        "schema_version": MANIFEST_SCHEMA,
        "tenant_id": str(action.tenant_id),
        "workspace_id": str(action.workspace_id),
        "action_id": str(action.id),
        "service_source_key": action.service_source_key,
        "control_title": action.control_title,
        "trigger_id": None if action.trigger_id is None else str(action.trigger_id),
        "recommendation_id": None if action.recommendation_id is None else str(action.recommendation_id),
        "request_id": None if action.request_id is None else str(action.request_id),
        "result_id": None if action.result_id is None else str(action.result_id),
        "decision_id": None if action.decision_id is None else str(action.decision_id),
        "evidence": [
            {
                "evidence_id": None if item.evidence_id is None else str(item.evidence_id),
                "hash": item.evidence_hash,
                "requirement_type": item.requirement_type,
                "status": item.status,
            }
            for item in requirements
        ],
        "closure_outcome": action.closure_outcome,
        "reviewer": action.closed_by or action.reviewer_subject,
        "closure_time": None if action.closed_at is None else action.closed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "evidence_hash_at_closure": action.evidence_hash_at_closure,
        "maturity": "Validated with reference data",
        "remaining_uncertainty": action.uncertain,
        "previous_manifest_id": previous_id,
        "is_signed": False,
    }
    canonical = json.dumps(body, separators=(",", ":"), sort_keys=True)
    return body, hashlib.sha256(canonical.encode()).hexdigest()


def _action_out(db: Session, action: ReadinessAction, *, detail: bool = False) -> dict:
    requirements = list(
        db.scalars(
            select(ReadinessClosureRequirement).where(
                ReadinessClosureRequirement.action_id == action.id,
                ReadinessClosureRequirement.workspace_id == action.workspace_id,
            )
        )
    )
    orphaned = False
    if action.owner_identity_id is not None:
        membership = db.scalar(
            select(WorkspaceMembership).where(
                WorkspaceMembership.workspace_id == action.workspace_id,
                WorkspaceMembership.identity_id == action.owner_identity_id,
            )
        )
        orphaned = membership is None
    manifest = db.scalar(
        select(ReadinessEvidenceManifest)
        .where(ReadinessEvidenceManifest.action_id == action.id)
        .order_by(ReadinessEvidenceManifest.generated_at.desc())
    )
    body = {
        "id": str(action.id),
        "status": action.status,
        "priority": action.priority,
        "title": action.title,
        "service": public_name(action.service_source_key),
        "service_source_key": action.service_source_key,
        "service_node_id": None if action.service_node_id is None else str(action.service_node_id),
        "control": action.control_title,
        "owner_subject": action.owner_subject,
        "owner_identity_id": None if action.owner_identity_id is None else str(action.owner_identity_id),
        "owner_orphaned": orphaned,
        "reviewer_subject": action.reviewer_subject,
        "due_at": None if action.due_at is None else action.due_at.isoformat(),
        "due_state": due_state(action),
        "maturity": "Validated with reference data",
        "recommendation_id": None if action.recommendation_id is None else str(action.recommendation_id),
        "request_id": None if action.request_id is None else str(action.request_id),
        "result_id": None if action.result_id is None else str(action.result_id),
        "decision_id": None if action.decision_id is None else str(action.decision_id),
        "closure_outcome": action.closure_outcome,
        "version": action.version,
        "requirements_complete": all(item.status == "satisfied" for item in requirements if item.mandatory),
        "requirements_pending": sum(1 for item in requirements if item.mandatory and item.status != "satisfied"),
        "manifest_digest": None if manifest is None else manifest.digest,
    }
    if detail:
        timeline = list(
            db.scalars(
                select(ReadinessAudit)
                .where(
                    ReadinessAudit.workspace_id == action.workspace_id,
                    ReadinessAudit.object_type == "action",
                    ReadinessAudit.object_id == action.id,
                )
                .order_by(ReadinessAudit.at.asc())
            )
        )
        body.update(
            {
                "why": action.why,
                "what_changed": action.what_changed,
                "required_work": action.required_work,
                "evidence_required": action.evidence_required,
                "known": action.known,
                "uncertain": action.uncertain,
                "closure_guidance": action.closure_guidance,
                "closure_rationale": action.closure_rationale,
                "reopen_reason": action.reopen_reason,
                "evidence_hash_at_closure": action.evidence_hash_at_closure,
                "requirements": [
                    {
                        "id": str(item.id),
                        "type": item.requirement_type,
                        "status": item.status,
                        "mandatory": item.mandatory,
                        "evidence_id": None if item.evidence_id is None else str(item.evidence_id),
                        "evidence_hash": item.evidence_hash,
                        "limitations": item.limitations,
                    }
                    for item in requirements
                ],
                "timeline": [
                    {"action": item.action, "actor": item.actor, "at": item.at.isoformat(), "payload": item.payload}
                    for item in timeline
                ],
                "allowed_transitions": sorted(TRANSITIONS.get(action.status, set())),
                "does_not_mean": "A closed action is not proof that related risk no longer exists.",
            }
        )
    return body


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


def _evidence_hashes(db: Session, action: ReadinessAction) -> list[str]:
    rows = list(
        db.scalars(
            select(ReadinessClosureRequirement).where(
                ReadinessClosureRequirement.action_id == action.id,
                ReadinessClosureRequirement.evidence_hash.is_not(None),
            )
        )
    )
    return sorted({row.evidence_hash for row in rows if row.evidence_hash})


def _active_member(db: Session, workspace_id: uuid.UUID, identity_id: uuid.UUID) -> tuple[Identity, str]:
    identity = db.get(Identity, identity_id)
    if identity is None or identity.status != "active":
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    membership = db.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace_id,
            WorkspaceMembership.identity_id == identity_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return identity, membership.subject


def _action(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, action_id: uuid.UUID) -> ReadinessAction:
    row = db.scalar(
        select(ReadinessAction).where(
            ReadinessAction.id == action_id,
            ReadinessAction.tenant_id == tenant_id,
            ReadinessAction.workspace_id == workspace_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


def _expect_version(action: ReadinessAction, expected: int | None) -> None:
    if expected is not None and expected != action.version:
        raise HTTPException(status_code=409, detail="Action version conflict")


def _require_write(role: str) -> None:
    if role not in REVIEW_ROLES:
        raise HTTPException(status_code=403, detail="Operator permission required")


def _audit(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, object_type: str, object_id: uuid.UUID, action: str, actor: str, payload: dict) -> None:
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
