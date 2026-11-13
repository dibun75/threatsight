"""Response workspace coordination service. Activation ≠ incident declaration."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import Identity, WorkspaceMembership
from threatsight_api.persistence.readiness_models import ReadinessAction
from threatsight_api.persistence.response_models import (
    ResponseActionLink,
    ResponseAuditEvent,
    ResponseCommunicationDraft,
    ResponseDecision,
    ResponseEvidenceRef,
    ResponseIntelligenceLink,
    ResponseJurisdictionProfile,
    ResponseRegulatoryAssessment,
    ResponseRoleAssignment,
    ResponseServiceLink,
    ResponseSituationReport,
    ResponseTimelineEntry,
    ResponseWorkspace,
)
from threatsight_api.response.vocabulary import (
    ADMIN_ROLES,
    COMM_TEMPLATES,
    CRITICAL_ROLES,
    DECLARATION_TRANSITIONS,
    DECLARATIONS,
    DRAFT_NOT_SENT_LABEL,
    EVIDENCE_ASSESSMENTS,
    LIFECYCLE_TRANSITIONS,
    LIFECYCLES,
    MODES,
    NOT_LEGAL_ADVICE,
    RESPONSE_ROLES,
    SYNTHETIC_EXERCISE_LABEL,
    TIMELINE_CATEGORIES,
    WRITE_ROLES,
)

_NOT_FOUND = "Response workspace not found"
_SAFE_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _now() -> datetime:
    return datetime.now(UTC)


def _clean(value: str, max_len: int) -> str:
    text = _SAFE_TEXT.sub("", (value or "").strip())
    if len(text) > max_len:
        raise HTTPException(status_code=400, detail=f"Field exceeds {max_len} characters")
    return text


def _require_write(role: str) -> None:
    if role not in WRITE_ROLES:
        raise HTTPException(status_code=403, detail="Insufficient role")


def _require_admin(role: str) -> None:
    if role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Administrator authorization required")


def _get(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, response_id: uuid.UUID) -> ResponseWorkspace:
    row = db.scalar(
        select(ResponseWorkspace).where(
            ResponseWorkspace.id == response_id,
            ResponseWorkspace.tenant_id == tenant_id,
            ResponseWorkspace.workspace_id == workspace_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


def _bump(row: ResponseWorkspace, expected_version: int | None) -> None:
    if expected_version is not None and row.version != expected_version:
        raise HTTPException(status_code=409, detail="Stale version")
    row.version += 1
    row.updated_at = _now()


def _audit(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID | None,
    event_type: str,
    actor: str,
    detail: dict[str, Any] | None = None,
) -> None:
    safe = {k: v for k, v in (detail or {}).items() if k not in {"token", "password", "secret", "private_key"}}
    db.add(
        ResponseAuditEvent(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            response_id=response_id,
            event_type=event_type[:64],
            actor=actor[:200],
            detail=safe,
        )
    )


def _timeline(
    db: Session,
    row: ResponseWorkspace,
    *,
    actor: str,
    category: str,
    summary: str,
    evidence_state: str = "unreviewed",
    linked: list[dict] | None = None,
    supersedes_id: uuid.UUID | None = None,
    correction_of_id: uuid.UUID | None = None,
    event_time: datetime | None = None,
) -> ResponseTimelineEntry:
    if category not in TIMELINE_CATEGORIES:
        raise HTTPException(status_code=400, detail="Invalid timeline category")
    if supersedes_id or correction_of_id:
        original_id = supersedes_id or correction_of_id
        original = db.scalar(
            select(ResponseTimelineEntry).where(
                ResponseTimelineEntry.id == original_id,
                ResponseTimelineEntry.response_id == row.id,
                ResponseTimelineEntry.workspace_id == row.workspace_id,
            )
        )
        if original is None:
            raise HTTPException(status_code=404, detail="Timeline entry not found")
        original.is_current = False
    entry = ResponseTimelineEntry(
        id=uuid.uuid4(),
        tenant_id=row.tenant_id,
        workspace_id=row.workspace_id,
        response_id=row.id,
        event_time=event_time or _now(),
        recorded_at=_now(),
        actor=actor[:200],
        category=category,
        summary=_clean(summary, 1000),
        linked_objects=linked or [],
        evidence_state=evidence_state if evidence_state in EVIDENCE_ASSESSMENTS else "unreviewed",
        supersedes_id=supersedes_id,
        correction_of_id=correction_of_id,
        is_current=True,
        provenance={"recorded_by": actor[:200]},
    )
    db.add(entry)
    db.flush()
    return entry


def _identity_in_workspace(db: Session, workspace_id: uuid.UUID, identity_id: uuid.UUID) -> Identity:
    identity = db.get(Identity, identity_id)
    if identity is None or identity.status != "active":
        raise HTTPException(status_code=400, detail="Identity unavailable")
    membership = db.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace_id,
            WorkspaceMembership.identity_id == identity_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=400, detail="Identity not in workspace")
    return identity


def _label_flags(row: ResponseWorkspace) -> dict[str, Any]:
    return {
        "is_synthetic": row.is_synthetic or row.mode == "exercise",
        "synthetic_label": SYNTHETIC_EXERCISE_LABEL if (row.is_synthetic or row.mode == "exercise") else None,
        "is_incident": row.declaration_state == "confirmed_incident",
        "mode_is_exercise": row.mode == "exercise",
    }


def _open_action_count(db: Session, response_id: uuid.UUID) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(ResponseActionLink)
            .join(ReadinessAction, ReadinessAction.id == ResponseActionLink.action_id)
            .where(
                ResponseActionLink.response_id == response_id,
                ResponseActionLink.active.is_(True),
                ReadinessAction.status.notin_(("closed", "cancelled", "superseded")),
            )
        )
        or 0
    )


def _lead_name(db: Session, response_id: uuid.UUID) -> str | None:
    assign = db.scalar(
        select(ResponseRoleAssignment).where(
            ResponseRoleAssignment.response_id == response_id,
            ResponseRoleAssignment.role_key == "response_lead",
            ResponseRoleAssignment.active.is_(True),
        )
    )
    return None if assign is None else assign.display_name or None


def serialize_summary(db: Session, row: ResponseWorkspace) -> dict[str, Any]:
    services = list(
        db.scalars(select(ResponseServiceLink).where(ResponseServiceLink.response_id == row.id).limit(20))
    )
    return {
        "id": str(row.id),
        "stable_key": row.stable_key,
        "title": row.title,
        "mode": row.mode,
        "lifecycle": row.lifecycle,
        "declaration_state": row.declaration_state,
        "evidence_assessment": row.evidence_assessment,
        "affected_services": [{"key": s.service_key, "name": s.service_name} for s in services],
        "response_lead": _lead_name(db, row.id),
        "open_actions": _open_action_count(db, row.id),
        "next_review_at": None if row.next_review_at is None else row.next_review_at.isoformat(),
        "version": row.version,
        **_label_flags(row),
    }


def serialize_detail(db: Session, row: ResponseWorkspace) -> dict[str, Any]:
    roles = list(
        db.scalars(
            select(ResponseRoleAssignment).where(
                ResponseRoleAssignment.response_id == row.id,
                ResponseRoleAssignment.active.is_(True),
            )
        )
    )
    filled = {r.role_key for r in roles}
    unfilled = [r for r in RESPONSE_ROLES if r not in filled]
    critical_unfilled = [r for r in CRITICAL_ROLES if r not in filled]
    actions = []
    for link in db.scalars(
        select(ResponseActionLink).where(ResponseActionLink.response_id == row.id, ResponseActionLink.active.is_(True))
    ):
        action = db.get(ReadinessAction, link.action_id)
        if action is None:
            continue
        actions.append(
            {
                "link_id": str(link.id),
                "action_id": str(action.id),
                "title": action.title,
                "status": action.status,
                "owner": action.owner_subject,
                "due_at": None if action.due_at is None else action.due_at.isoformat(),
                "evidence_required": action.evidence_required,
                "response_role": link.response_role,
                "closure_outcome": action.closure_outcome,
                "reopened": action.status == "reopened",
            }
        )
    timeline = [
        {
            "id": str(e.id),
            "event_time": e.event_time.isoformat(),
            "recorded_at": e.recorded_at.isoformat(),
            "actor": e.actor,
            "category": e.category,
            "summary": e.summary,
            "evidence_state": e.evidence_state,
            "is_current": e.is_current,
            "supersedes_id": None if e.supersedes_id is None else str(e.supersedes_id),
            "correction_of_id": None if e.correction_of_id is None else str(e.correction_of_id),
        }
        for e in db.scalars(
            select(ResponseTimelineEntry)
            .where(ResponseTimelineEntry.response_id == row.id)
            .order_by(ResponseTimelineEntry.event_time.desc())
            .limit(200)
        )
    ]
    decisions = [
        {
            "id": str(d.id),
            "decision": d.decision,
            "rationale": d.rationale,
            "decision_maker": d.decision_maker,
            "remaining_uncertainty": d.remaining_uncertainty,
            "effective_at": d.effective_at.isoformat(),
            "review_at": None if d.review_at is None else d.review_at.isoformat(),
        }
        for d in db.scalars(select(ResponseDecision).where(ResponseDecision.response_id == row.id).limit(100))
    ]
    return {
        **serialize_summary(db, row),
        "reason": row.reason,
        "known_facts": row.known_facts,
        "uncertain_facts": row.uncertain_facts,
        "operational_impact": row.operational_impact,
        "external_communication_state": row.external_communication_state,
        "regulatory_profile_state": row.regulatory_profile_state,
        "remaining_uncertainty": row.remaining_uncertainty,
        "activation_rationale": row.activation_rationale,
        "declaration_rationale": row.declaration_rationale,
        "activated_at": None if row.activated_at is None else row.activated_at.isoformat(),
        "declared_at": None if row.declared_at is None else row.declared_at.isoformat(),
        "closure_notes": row.closure_notes,
        "lessons_learned": row.lessons_learned,
        "roles": [
            {
                "id": str(r.id),
                "role_key": r.role_key,
                "identity_id": None if r.identity_id is None else str(r.identity_id),
                "display_name": r.display_name,
                "is_orphan": r.is_orphan,
                "is_synthetic": r.is_synthetic,
            }
            for r in roles
        ],
        "unfilled_roles": unfilled,
        "critical_unfilled_roles": critical_unfilled,
        "services": [
            {
                "id": str(s.id),
                "service_key": s.service_key,
                "service_name": s.service_name,
                "involvement": s.involvement,
                "notes": s.notes,
            }
            for s in db.scalars(select(ResponseServiceLink).where(ResponseServiceLink.response_id == row.id))
        ],
        "actions": actions,
        "timeline": timeline,
        "decisions": decisions,
        "evidence_refs": [
            {
                "id": str(e.id),
                "ref_kind": e.ref_kind,
                "ref_id": str(e.ref_id),
                "label": e.label,
                "evidence_assessment": e.evidence_assessment,
                "content_hash": e.content_hash,
            }
            for e in db.scalars(select(ResponseEvidenceRef).where(ResponseEvidenceRef.response_id == row.id).limit(100))
        ],
        "not_legal_advice": NOT_LEGAL_ADVICE,
    }


def command_center_summary(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(ResponseWorkspace).where(
                ResponseWorkspace.tenant_id == tenant_id,
                ResponseWorkspace.workspace_id == workspace_id,
                ResponseWorkspace.lifecycle.in_(("monitoring", "assessing", "activated", "recovery_review")),
            )
        )
    )
    overdue = 0
    now = _now()
    for row in rows:
        for d in db.scalars(select(ResponseDecision).where(ResponseDecision.response_id == row.id)):
            if d.review_at is not None and d.review_at < now:
                overdue += 1
    critical_gaps = 0
    for row in rows:
        filled = {
            a.role_key
            for a in db.scalars(
                select(ResponseRoleAssignment).where(
                    ResponseRoleAssignment.response_id == row.id,
                    ResponseRoleAssignment.active.is_(True),
                )
            )
        }
        if CRITICAL_ROLES - filled:
            critical_gaps += 1
    return {
        "assessments_active": sum(1 for r in rows if r.mode == "assessment"),
        "exercises_active": sum(1 for r in rows if r.mode == "exercise"),
        "confirmed_incidents": sum(1 for r in rows if r.declaration_state == "confirmed_incident"),
        "decisions_overdue": overdue,
        "unfilled_critical_roles": critical_gaps,
        "note": "Exercises are not incidents.",
    }


def list_responses(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    *,
    limit: int = 50,
    offset: int = 0,
    mode: str | None = None,
    lifecycle: str | None = None,
) -> dict[str, Any]:
    q = select(ResponseWorkspace).where(
        ResponseWorkspace.tenant_id == tenant_id,
        ResponseWorkspace.workspace_id == workspace_id,
    )
    if mode:
        if mode not in MODES:
            raise HTTPException(status_code=400, detail="Invalid mode filter")
        q = q.where(ResponseWorkspace.mode == mode)
    if lifecycle:
        if lifecycle not in LIFECYCLES:
            raise HTTPException(status_code=400, detail="Invalid lifecycle filter")
        q = q.where(ResponseWorkspace.lifecycle == lifecycle)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = list(db.scalars(q.order_by(ResponseWorkspace.updated_at.desc()).offset(offset).limit(limit)))
    return {"items": [serialize_summary(db, r) for r in rows], "total": int(total), "limit": limit, "offset": offset}


def propose(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    title: str,
    reason: str,
    mode: str = "assessment",
    stable_key: str | None = None,
    idempotency_key: str,
    known_facts: str = "",
    uncertain_facts: str = "",
    operational_impact: str = "",
    is_synthetic: bool = False,
    services: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    _require_write(role)
    if mode not in MODES:
        raise HTTPException(status_code=400, detail="Invalid mode")
    idem = _clean(idempotency_key, 200)
    existing = db.scalar(
        select(ResponseWorkspace).where(
            ResponseWorkspace.workspace_id == workspace_id,
            ResponseWorkspace.idempotency_key == idem,
        )
    )
    if existing is not None:
        return serialize_detail(db, existing)
    key = _clean(stable_key or f"resp-{uuid.uuid4().hex[:12]}", 128)
    synthetic = is_synthetic or mode == "exercise"
    row = ResponseWorkspace(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        stable_key=key,
        title=_clean(title, 300),
        mode=mode,
        lifecycle="draft",
        declaration_state="not_declared",
        evidence_assessment="unreviewed",
        reason=_clean(reason, 2000),
        known_facts=_clean(known_facts, 4000),
        uncertain_facts=_clean(uncertain_facts, 4000),
        operational_impact=_clean(operational_impact, 2000),
        is_synthetic=synthetic,
        classification="synthetic_exercise" if synthetic else "operational",
        idempotency_key=idem,
        created_by=actor[:200],
    )
    db.add(row)
    db.flush()
    for svc in services or []:
        db.add(
            ResponseServiceLink(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                response_id=row.id,
                service_key=_clean(svc.get("service_key", ""), 128),
                service_name=_clean(svc.get("service_name", svc.get("service_key", "")), 300),
                involvement=_clean(svc.get("involvement", "potentially_affected"), 64),
                notes=_clean(svc.get("notes", ""), 1000),
                created_by=actor[:200],
            )
        )
    _timeline(db, row, actor=actor, category="assessment_update", summary=f"Proposed: {row.title}")
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="creation",
        actor=actor,
        detail={"mode": mode, "lifecycle": "draft"},
    )
    db.flush()
    return serialize_detail(db, row)


def activate(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    rationale: str,
    expected_version: int | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    _require_admin(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    if row.lifecycle not in LIFECYCLE_TRANSITIONS or "activated" not in LIFECYCLE_TRANSITIONS[row.lifecycle]:
        raise HTTPException(status_code=400, detail="Invalid lifecycle transition")
    rationale_clean = _clean(rationale, 2000)
    if len(rationale_clean) < 8:
        raise HTTPException(status_code=400, detail="Activation rationale required")
    _bump(row, expected_version)
    if mode is not None:
        if mode not in MODES:
            raise HTTPException(status_code=400, detail="Invalid mode")
        if mode != row.mode:
            _audit(
                db,
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                response_id=row.id,
                event_type="mode_change",
                actor=actor,
                detail={"from": row.mode, "to": mode},
            )
            row.mode = mode
            if mode == "exercise":
                row.is_synthetic = True
                row.classification = "synthetic_exercise"
    row.lifecycle = "activated"
    row.activated_at = _now()
    row.activated_by = actor[:200]
    row.activation_rationale = rationale_clean
    _timeline(db, row, actor=actor, category="assessment_update", summary=f"Activated as {row.mode}: {rationale_clean[:200]}")
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="activation",
        actor=actor,
        detail={"mode": row.mode, "rationale": rationale_clean[:200]},
    )
    db.flush()
    return serialize_detail(db, row)


def change_declaration(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    declaration_state: str,
    rationale: str,
    remaining_uncertainty: str,
    expected_version: int | None = None,
    evidence_reviewed: bool = False,
) -> dict[str, Any]:
    _require_admin(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    if declaration_state not in DECLARATIONS:
        raise HTTPException(status_code=400, detail="Invalid declaration state")
    allowed = DECLARATION_TRANSITIONS.get(row.declaration_state, frozenset())
    if declaration_state not in allowed:
        raise HTTPException(status_code=400, detail="Invalid declaration transition")
    if declaration_state == "confirmed_incident":
        if row.lifecycle != "activated":
            raise HTTPException(status_code=400, detail="Confirmed incident requires activated workspace")
        if not evidence_reviewed:
            raise HTTPException(status_code=400, detail="Reviewed supporting evidence required")
        if row.mode == "exercise":
            raise HTTPException(status_code=400, detail="Exercise cannot become a confirmed incident")
        # Require at least one evidence ref assessed as supported or suspected
        refs = list(db.scalars(select(ResponseEvidenceRef).where(ResponseEvidenceRef.response_id == row.id)))
        if not any(r.evidence_assessment in {"supported", "suspected"} for r in refs):
            raise HTTPException(status_code=400, detail="Supporting evidence required for confirmed incident")
    rationale_clean = _clean(rationale, 2000)
    if len(rationale_clean) < 8:
        raise HTTPException(status_code=400, detail="Declaration rationale required")
    prev = row.declaration_state
    _bump(row, expected_version)
    row.declaration_state = declaration_state
    row.declaration_rationale = rationale_clean
    row.remaining_uncertainty = _clean(remaining_uncertainty, 2000)
    row.declared_at = _now()
    row.declared_by = actor[:200]
    _timeline(
        db,
        row,
        actor=actor,
        category="declaration_change",
        summary=f"Declaration {prev} → {declaration_state}: {rationale_clean[:200]}",
        evidence_state=row.evidence_assessment,
    )
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="declaration_change",
        actor=actor,
        detail={"from": prev, "to": declaration_state},
    )
    db.flush()
    return serialize_detail(db, row)


def assign_role(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    role_key: str,
    identity_id: uuid.UUID,
    notes: str = "",
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    if role_key not in RESPONSE_ROLES:
        raise HTTPException(status_code=400, detail="Invalid response role")
    identity = _identity_in_workspace(db, workspace_id, identity_id)
    # Deactivate prior active assignment for same role+identity to keep history
    prior = list(
        db.scalars(
            select(ResponseRoleAssignment).where(
                ResponseRoleAssignment.response_id == row.id,
                ResponseRoleAssignment.role_key == role_key,
                ResponseRoleAssignment.identity_id == identity_id,
                ResponseRoleAssignment.active.is_(True),
            )
        )
    )
    for p in prior:
        p.active = False
        p.unassigned_at = _now()
        p.unassigned_by = actor[:200]
    assignment = ResponseRoleAssignment(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        role_key=role_key,
        identity_id=identity.id,
        display_name=(identity.display_name or identity.subject)[:200],
        is_orphan=False,
        is_synthetic=row.is_synthetic or row.mode == "exercise",
        assigned_by=actor[:200],
        notes=_clean(notes, 500),
        active=True,
    )
    db.add(assignment)
    _timeline(
        db,
        row,
        actor=actor,
        category="role_assignment",
        summary=f"Assigned {role_key} to {assignment.display_name}",
        linked=[{"type": "identity", "id": str(identity.id)}],
    )
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="role_assignment",
        actor=actor,
        detail={"role_key": role_key, "identity_id": str(identity.id)},
    )
    if role_key == "response_lead":
        row.owner_identity_id = identity.id
    db.flush()
    return serialize_detail(db, row)


def link_action(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    action_id: uuid.UUID,
    response_role: str = "",
    notes: str = "",
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    action = db.scalar(
        select(ReadinessAction).where(
            ReadinessAction.id == action_id,
            ReadinessAction.tenant_id == tenant_id,
            ReadinessAction.workspace_id == workspace_id,
        )
    )
    if action is None:
        raise HTTPException(status_code=404, detail="Action not found")
    existing = db.scalar(
        select(ResponseActionLink).where(
            ResponseActionLink.response_id == row.id,
            ResponseActionLink.action_id == action_id,
        )
    )
    if existing is not None:
        existing.active = True
        existing.response_role = _clean(response_role, 64)
        existing.notes = _clean(notes, 500)
        link = existing
    else:
        link = ResponseActionLink(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            response_id=row.id,
            action_id=action_id,
            response_role=_clean(response_role, 64),
            linked_by=actor[:200],
            notes=_clean(notes, 500),
            active=True,
        )
        db.add(link)
    _timeline(
        db,
        row,
        actor=actor,
        category="action_update",
        summary=f"Linked action: {action.title}",
        linked=[{"type": "action", "id": str(action.id)}],
    )
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="action_linkage",
        actor=actor,
        detail={"action_id": str(action_id)},
    )
    db.flush()
    return serialize_detail(db, row)


def unlink_action(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    action_id: uuid.UUID,
    *,
    actor: str,
    role: str,
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    link = db.scalar(
        select(ResponseActionLink).where(
            ResponseActionLink.response_id == row.id,
            ResponseActionLink.action_id == action_id,
            ResponseActionLink.workspace_id == workspace_id,
        )
    )
    if link is None:
        raise HTTPException(status_code=404, detail="Action link not found")
    link.active = False
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="action_linkage",
        actor=actor,
        detail={"action_id": str(action_id), "unlinked": True},
    )
    db.flush()
    return serialize_detail(db, row)


def add_timeline_entry(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    category: str,
    summary: str,
    evidence_state: str = "unreviewed",
    event_time: datetime | None = None,
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    entry = _timeline(
        db,
        row,
        actor=actor,
        category=category,
        summary=summary,
        evidence_state=evidence_state,
        event_time=event_time,
    )
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="timeline_entry",
        actor=actor,
        detail={"entry_id": str(entry.id), "category": category},
    )
    db.flush()
    return {"entry_id": str(entry.id), "response": serialize_detail(db, row)}


def correct_timeline_entry(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    entry_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    summary: str,
    category: str | None = None,
    evidence_state: str = "unreviewed",
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    original = db.scalar(
        select(ResponseTimelineEntry).where(
            ResponseTimelineEntry.id == entry_id,
            ResponseTimelineEntry.response_id == row.id,
            ResponseTimelineEntry.workspace_id == workspace_id,
        )
    )
    if original is None:
        raise HTTPException(status_code=404, detail="Timeline entry not found")
    entry = _timeline(
        db,
        row,
        actor=actor,
        category=category or original.category,
        summary=summary,
        evidence_state=evidence_state,
        correction_of_id=original.id,
        supersedes_id=original.id,
    )
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="timeline_correction",
        actor=actor,
        detail={"original_id": str(original.id), "entry_id": str(entry.id)},
    )
    db.flush()
    return {"entry_id": str(entry.id), "response": serialize_detail(db, row)}


def add_decision(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    decision: str,
    rationale: str,
    evidence_considered: str = "",
    alternatives: str = "",
    remaining_uncertainty: str = "",
    idempotency_key: str,
    review_at: datetime | None = None,
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    idem = _clean(idempotency_key, 200)
    existing = db.scalar(
        select(ResponseDecision).where(
            ResponseDecision.response_id == row.id,
            ResponseDecision.idempotency_key == idem,
        )
    )
    if existing is not None:
        return {"decision_id": str(existing.id), "response": serialize_detail(db, row)}
    entry = _timeline(
        db,
        row,
        actor=actor,
        category="decision",
        summary=_clean(decision, 500),
    )
    dec = ResponseDecision(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        decision=_clean(decision, 500),
        rationale=_clean(rationale, 4000),
        decision_maker=actor[:200],
        evidence_considered=_clean(evidence_considered, 4000),
        alternatives=_clean(alternatives, 2000),
        remaining_uncertainty=_clean(remaining_uncertainty, 2000),
        effective_at=_now(),
        review_at=review_at,
        timeline_entry_id=entry.id,
        idempotency_key=idem,
    )
    db.add(dec)
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="decision",
        actor=actor,
        detail={"decision_id": str(dec.id)},
    )
    db.flush()
    return {"decision_id": str(dec.id), "response": serialize_detail(db, row)}


def pin_evidence(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    ref_kind: str,
    ref_id: uuid.UUID,
    label: str = "",
    evidence_assessment: str = "unreviewed",
    content_hash: str | None = None,
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    if evidence_assessment not in EVIDENCE_ASSESSMENTS:
        raise HTTPException(status_code=400, detail="Invalid evidence assessment")
    # Reject client-trusted hashes that look like arbitrary injection — store only server-known or None
    stored_hash = None
    if content_hash is not None:
        h = content_hash.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", h):
            stored_hash = h
        else:
            raise HTTPException(status_code=400, detail="Invalid content hash")
    existing = db.scalar(
        select(ResponseEvidenceRef).where(
            ResponseEvidenceRef.response_id == row.id,
            ResponseEvidenceRef.ref_kind == _clean(ref_kind, 64),
            ResponseEvidenceRef.ref_id == ref_id,
        )
    )
    if existing is not None:
        existing.evidence_assessment = evidence_assessment
        existing.label = _clean(label or existing.label, 300)
        return serialize_detail(db, row)
    db.add(
        ResponseEvidenceRef(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            response_id=row.id,
            ref_kind=_clean(ref_kind, 64),
            ref_id=ref_id,
            content_hash=stored_hash,
            label=_clean(label, 300),
            evidence_assessment=evidence_assessment,
            pinned_by=actor[:200],
        )
    )
    _timeline(
        db,
        row,
        actor=actor,
        category="evidence_added",
        summary=f"Pinned evidence {_clean(ref_kind, 64)}",
        evidence_state=evidence_assessment,
        linked=[{"type": ref_kind, "id": str(ref_id)}],
    )
    db.flush()
    return serialize_detail(db, row)


def create_sitrep(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    max_v = db.scalar(
        select(func.coalesce(func.max(ResponseSituationReport.version_number), 0)).where(
            ResponseSituationReport.response_id == row.id
        )
    )
    report = ResponseSituationReport(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        version_number=int(max_v or 0) + 1,
        status="draft",
        current_status=_clean(fields.get("current_status", row.lifecycle), 2000),
        what_changed=_clean(fields.get("what_changed", ""), 2000),
        business_services=_clean(fields.get("business_services", ""), 2000),
        known_facts=_clean(fields.get("known_facts", row.known_facts), 4000),
        uncertain_facts=_clean(fields.get("uncertain_facts", row.uncertain_facts), 4000),
        actions_and_owners=_clean(fields.get("actions_and_owners", ""), 4000),
        decisions_required=_clean(fields.get("decisions_required", ""), 2000),
        evidence_freshness=_clean(fields.get("evidence_freshness", ""), 1000),
        external_communication_state=_clean(
            fields.get("external_communication_state", row.external_communication_state), 500
        ),
        regulatory_assessment_state=_clean(
            fields.get("regulatory_assessment_state", row.regulatory_profile_state), 500
        ),
        next_review_at=row.next_review_at,
        created_by=actor[:200],
    )
    db.add(report)
    _timeline(
        db,
        row,
        actor=actor,
        category="situation_report",
        summary=f"Situation report draft v{report.version_number}",
    )
    db.flush()
    return _sitrep_out(report, row)


def finalize_sitrep(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    report_id: uuid.UUID,
    *,
    actor: str,
    role: str,
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    report = db.scalar(
        select(ResponseSituationReport).where(
            ResponseSituationReport.id == report_id,
            ResponseSituationReport.response_id == row.id,
            ResponseSituationReport.workspace_id == workspace_id,
        )
    )
    if report is None:
        raise HTTPException(status_code=404, detail="Situation report not found")
    if report.status == "final":
        return _sitrep_out(report, row)
    # Reject unsupported containment/recovery language
    blob = f"{report.current_status} {report.what_changed} {report.known_facts} {report.uncertain_facts}".lower()
    for banned in ("fully contained", "eradicated", "full recovery confirmed", "compromise confirmed"):
        if banned in blob and "not " not in blob:
            raise HTTPException(status_code=400, detail="Unsupported containment/recovery language")
    report.status = "final"
    report.reviewed_by = actor[:200]
    report.finalized_at = _now()
    report.finalized_by = actor[:200]
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="report_finalization",
        actor=actor,
        detail={"report_id": str(report.id), "version": report.version_number},
    )
    db.flush()
    return _sitrep_out(report, row)


def _sitrep_out(report: ResponseSituationReport, row: ResponseWorkspace) -> dict[str, Any]:
    return {
        "id": str(report.id),
        "response_id": str(row.id),
        "version_number": report.version_number,
        "status": report.status,
        "declaration_state": row.declaration_state,
        "mode": row.mode,
        "synthetic_label": SYNTHETIC_EXERCISE_LABEL if (row.is_synthetic or row.mode == "exercise") else None,
        "current_status": report.current_status,
        "what_changed": report.what_changed,
        "business_services": report.business_services,
        "known_facts": report.known_facts,
        "uncertain_facts": report.uncertain_facts,
        "actions_and_owners": report.actions_and_owners,
        "decisions_required": report.decisions_required,
        "evidence_freshness": report.evidence_freshness,
        "external_communication_state": report.external_communication_state,
        "regulatory_assessment_state": report.regulatory_assessment_state,
        "next_review_at": None if report.next_review_at is None else report.next_review_at.isoformat(),
        "finalized_at": None if report.finalized_at is None else report.finalized_at.isoformat(),
        "printable": True,
    }


def create_comm_draft(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    template_key: str,
    subject: str,
    body_text: str,
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    if template_key not in COMM_TEMPLATES:
        raise HTTPException(status_code=400, detail="Invalid template")
    max_v = db.scalar(
        select(func.coalesce(func.max(ResponseCommunicationDraft.version_number), 0)).where(
            ResponseCommunicationDraft.response_id == row.id,
            ResponseCommunicationDraft.template_key == template_key,
        )
    )
    draft = ResponseCommunicationDraft(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        template_key=template_key,
        version_number=int(max_v or 0) + 1,
        subject=_clean(subject, 300),
        body_text=_clean(body_text, 8000),
        approval_status="draft",
        delivery_state="not_sent",
        created_by=actor[:200],
    )
    db.add(draft)
    row.external_communication_state = "draft_only"
    _timeline(
        db,
        row,
        actor=actor,
        category="communication_draft",
        summary=f"{DRAFT_NOT_SENT_LABEL}: {template_key} v{draft.version_number}",
    )
    db.flush()
    return _comm_out(draft, row)


def approve_comm_draft(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    draft_id: uuid.UUID,
    *,
    actor: str,
    role: str,
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    draft = db.scalar(
        select(ResponseCommunicationDraft).where(
            ResponseCommunicationDraft.id == draft_id,
            ResponseCommunicationDraft.response_id == row.id,
        )
    )
    if draft is None:
        raise HTTPException(status_code=404, detail="Draft not found")
    draft.approval_status = "approved_draft"
    draft.approved_by = actor[:200]
    draft.approved_at = _now()
    draft.delivery_state = "not_sent"
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="communication_approval",
        actor=actor,
        detail={"draft_id": str(draft.id), "delivery_state": "not_sent"},
    )
    db.flush()
    return _comm_out(draft, row)


def _comm_out(draft: ResponseCommunicationDraft, row: ResponseWorkspace) -> dict[str, Any]:
    return {
        "id": str(draft.id),
        "template_key": draft.template_key,
        "version_number": draft.version_number,
        "subject": draft.subject,
        "body_text": draft.body_text,
        "approval_status": draft.approval_status,
        "delivery_state": draft.delivery_state,
        "label": DRAFT_NOT_SENT_LABEL,
        "synthetic_label": SYNTHETIC_EXERCISE_LABEL if (row.is_synthetic or row.mode == "exercise") else None,
        "sent": False,
    }


def list_jurisdiction_profiles(db: Session) -> dict[str, Any]:
    rows = list(db.scalars(select(ResponseJurisdictionProfile).where(ResponseJurisdictionProfile.active.is_(True))))
    return {
        "items": [
            {
                "id": str(p.id),
                "profile_key": p.profile_key,
                "title": p.title,
                "jurisdiction": p.jurisdiction,
                "source_urls": p.source_urls,
                "reviewed_at": p.reviewed_at.isoformat(),
                "summary": p.summary,
                "uncertainty_notes": p.uncertainty_notes,
                "default_deadline_hours": p.default_deadline_hours,
                "not_legal_advice": p.not_legal_advice,
            }
            for p in rows
        ],
        "not_legal_advice": NOT_LEGAL_ADVICE,
    }


def upsert_regulatory(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    profile_id: uuid.UUID,
    legal_applicability: str = "not_determined",
    reporting_obligation: str = "not_determined",
    deadline_hours_confirmed: int | None = None,
    confirm_deadline: bool = False,
    liaison_confirmed: bool = False,
    liaison_identity_id: uuid.UUID | None = None,
    evidence_notes: str = "",
    expected_version: int | None = None,
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    profile = db.get(ResponseJurisdictionProfile, profile_id)
    if profile is None or not profile.active:
        raise HTTPException(status_code=404, detail="Jurisdiction profile not found")
    if legal_applicability not in {
        "not_determined",
        "possibly_applicable",
        "not_applicable",
        "confirmed_applicable",
    }:
        raise HTTPException(status_code=400, detail="Invalid applicability")
    if reporting_obligation not in {
        "not_determined",
        "possibly_required",
        "not_required",
        "confirmed_required",
    }:
        raise HTTPException(status_code=400, detail="Invalid reporting obligation")
    if legal_applicability == "confirmed_applicable" and not liaison_confirmed:
        raise HTTPException(status_code=400, detail="Legal/regulatory liaison confirmation required")
    if deadline_hours_confirmed is not None and not confirm_deadline:
        raise HTTPException(status_code=400, detail="Deadline requires explicit operator confirmation")
    if liaison_identity_id is not None:
        _identity_in_workspace(db, workspace_id, liaison_identity_id)
    reg = db.scalar(select(ResponseRegulatoryAssessment).where(ResponseRegulatoryAssessment.response_id == row.id))
    if reg is None:
        reg = ResponseRegulatoryAssessment(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            response_id=row.id,
            profile_id=profile_id,
            updated_by=actor[:200],
        )
        db.add(reg)
    else:
        if expected_version is not None and reg.version != expected_version:
            raise HTTPException(status_code=409, detail="Stale version")
        reg.version += 1
    reg.profile_id = profile_id
    reg.legal_applicability = legal_applicability
    reg.reporting_obligation = reporting_obligation
    reg.liaison_confirmed = liaison_confirmed
    reg.liaison_identity_id = liaison_identity_id
    reg.evidence_notes = _clean(evidence_notes, 4000)
    reg.updated_by = actor[:200]
    if confirm_deadline and deadline_hours_confirmed is not None:
        reg.deadline_hours_confirmed = deadline_hours_confirmed
        reg.deadline_confirmed_by = actor[:200]
        reg.deadline_confirmed_at = _now()
    row.regulatory_profile_state = "selected_not_determined" if legal_applicability == "not_determined" else legal_applicability
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="regulatory_assessment",
        actor=actor,
        detail={
            "profile_key": profile.profile_key,
            "legal_applicability": legal_applicability,
            "reporting_obligation": reporting_obligation,
        },
    )
    db.flush()
    return {
        "id": str(reg.id),
        "profile_key": profile.profile_key,
        "legal_applicability": reg.legal_applicability,
        "reporting_obligation": reg.reporting_obligation,
        "deadline_hours_confirmed": reg.deadline_hours_confirmed,
        "liaison_confirmed": reg.liaison_confirmed,
        "not_legal_advice": NOT_LEGAL_ADVICE,
        "regulator_notified": False,
        "version": reg.version,
    }


def close_response(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    notes: str,
    lessons_learned: str = "",
    expected_version: int | None = None,
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    if row.lifecycle not in {"activated", "recovery_review", "assessing", "monitoring"}:
        raise HTTPException(status_code=400, detail="Cannot close from current lifecycle")
    _bump(row, expected_version)
    row.lifecycle = "closed"
    row.closed_at = _now()
    row.closed_by = actor[:200]
    row.closure_notes = _clean(notes, 4000)
    row.lessons_learned = _clean(lessons_learned, 4000)
    _timeline(db, row, actor=actor, category="closure_reopen", summary=f"Closed: {_clean(notes, 200)}")
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="closure",
        actor=actor,
        detail={},
    )
    db.flush()
    return serialize_detail(db, row)


def reopen_response(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    reason: str,
    expected_version: int | None = None,
) -> dict[str, Any]:
    _require_admin(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    if row.lifecycle != "closed":
        raise HTTPException(status_code=400, detail="Only closed workspaces can be reopened")
    _bump(row, expected_version)
    row.lifecycle = "assessing"
    row.closed_at = None
    _timeline(db, row, actor=actor, category="closure_reopen", summary=f"Reopened: {_clean(reason, 200)}")
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="reopen",
        actor=actor,
        detail={"reason": _clean(reason, 200)},
    )
    db.flush()
    return serialize_detail(db, row)


def cancel_response(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    reason: str,
    expected_version: int | None = None,
) -> dict[str, Any]:
    _require_admin(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    if row.lifecycle not in {"draft", "monitoring", "assessing"}:
        raise HTTPException(status_code=400, detail="Cannot cancel from current lifecycle")
    _bump(row, expected_version)
    row.lifecycle = "cancelled"
    _timeline(db, row, actor=actor, category="closure_reopen", summary=f"Cancelled: {_clean(reason, 200)}")
    _audit(
        db,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        response_id=row.id,
        event_type="cancel",
        actor=actor,
        detail={},
    )
    db.flush()
    return serialize_detail(db, row)


def build_snapshot_payload(db: Session, row: ResponseWorkspace) -> dict[str, Any]:
    detail = serialize_detail(db, row)
    # Strip any accidental secret-looking keys
    payload = {
        "schema": "threatsight.response_snapshot.v1",
        "response_id": str(row.id),
        "stable_key": row.stable_key,
        "title": row.title,
        "mode": row.mode,
        "lifecycle": row.lifecycle,
        "declaration_state": row.declaration_state,
        "evidence_assessment": row.evidence_assessment,
        "is_synthetic": row.is_synthetic or row.mode == "exercise",
        "services": detail["services"],
        "roles": detail["roles"],
        "open_actions": [a for a in detail["actions"] if a["status"] not in {"closed", "cancelled", "superseded"}],
        "decisions": detail["decisions"],
        "evidence_refs": detail["evidence_refs"],
        "known_facts": row.known_facts,
        "uncertain_facts": row.uncertain_facts,
        "remaining_uncertainty": row.remaining_uncertainty,
        "generated_at": _now().isoformat(),
        "integrity_disclaimer": (
            "Signature proves snapshot integrity only—not incident truth, compliance, or legal validity."
        ),
    }
    return payload


def create_snapshot(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    idempotency_key: str,
) -> dict[str, Any]:
    from threatsight_api.response.snapshots import finalize_and_request_signature

    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    return finalize_and_request_signature(
        db,
        row,
        actor=actor,
        role=role,
        idempotency_key=_clean(idempotency_key, 200),
    )


def link_intelligence(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    response_id: uuid.UUID,
    *,
    actor: str,
    role: str,
    link_type: str,
    target_id: uuid.UUID,
    label: str = "",
    evidence_assessment: str = "unreviewed",
    notes: str = "",
) -> dict[str, Any]:
    _require_write(role)
    row = _get(db, tenant_id, workspace_id, response_id)
    existing = db.scalar(
        select(ResponseIntelligenceLink).where(
            ResponseIntelligenceLink.response_id == row.id,
            ResponseIntelligenceLink.link_type == _clean(link_type, 64),
            ResponseIntelligenceLink.target_id == target_id,
        )
    )
    if existing is None:
        db.add(
            ResponseIntelligenceLink(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                response_id=row.id,
                link_type=_clean(link_type, 64),
                target_id=target_id,
                label=_clean(label, 300),
                evidence_assessment=evidence_assessment if evidence_assessment in EVIDENCE_ASSESSMENTS else "unreviewed",
                notes=_clean(notes, 1000),
                created_by=actor[:200],
            )
        )
        _timeline(
            db,
            row,
            actor=actor,
            category="intelligence_change",
            summary=f"Linked intelligence {_clean(link_type, 64)}",
            evidence_state=evidence_assessment,
        )
    db.flush()
    return serialize_detail(db, row)


def digest_payload(payload: dict[str, Any]) -> tuple[str, str]:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return canonical, digest
