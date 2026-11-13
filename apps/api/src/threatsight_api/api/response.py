"""Workspace-scoped response workspace APIs (Phase 3E)."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, WorkspaceScope
from threatsight_api.persistence.response_models import (
    ResponseSituationReport,
    ResponseSnapshot,
)
from threatsight_api.response import service as response_service

router = APIRouter(prefix="/response", tags=["response"])


class ProposeBody(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    reason: str = Field(min_length=8, max_length=2000)
    mode: str = Field(default="assessment", pattern="^(assessment|exercise|incident_response)$")
    stable_key: str | None = Field(default=None, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=200)
    known_facts: str = Field(default="", max_length=4000)
    uncertain_facts: str = Field(default="", max_length=4000)
    operational_impact: str = Field(default="", max_length=2000)
    is_synthetic: bool = False
    services: list[dict[str, str]] = Field(default_factory=list, max_length=50)


class ActivateBody(BaseModel):
    rationale: str = Field(min_length=8, max_length=2000)
    expected_version: int | None = None
    mode: str | None = Field(default=None, pattern="^(assessment|exercise|incident_response)$")


class DeclarationBody(BaseModel):
    declaration_state: str = Field(pattern="^(not_declared|suspected_incident|confirmed_incident|ruled_out)$")
    rationale: str = Field(min_length=8, max_length=2000)
    remaining_uncertainty: str = Field(default="", max_length=2000)
    evidence_reviewed: bool = False
    expected_version: int | None = None


class RoleBody(BaseModel):
    role_key: str = Field(max_length=64)
    identity_id: uuid.UUID
    notes: str = Field(default="", max_length=500)


class ActionLinkBody(BaseModel):
    action_id: uuid.UUID
    response_role: str = Field(default="", max_length=64)
    notes: str = Field(default="", max_length=500)


class TimelineBody(BaseModel):
    category: str = Field(max_length=64)
    summary: str = Field(min_length=1, max_length=1000)
    evidence_state: str = Field(default="unreviewed", max_length=32)
    event_time: datetime | None = None


class TimelineCorrectBody(BaseModel):
    summary: str = Field(min_length=1, max_length=1000)
    category: str | None = Field(default=None, max_length=64)
    evidence_state: str = Field(default="unreviewed", max_length=32)


class DecisionBody(BaseModel):
    decision: str = Field(min_length=1, max_length=500)
    rationale: str = Field(min_length=1, max_length=4000)
    evidence_considered: str = Field(default="", max_length=4000)
    alternatives: str = Field(default="", max_length=2000)
    remaining_uncertainty: str = Field(default="", max_length=2000)
    idempotency_key: str = Field(min_length=8, max_length=200)
    review_at: datetime | None = None


class EvidencePinBody(BaseModel):
    ref_kind: str = Field(min_length=1, max_length=64)
    ref_id: uuid.UUID
    label: str = Field(default="", max_length=300)
    evidence_assessment: str = Field(default="unreviewed", max_length=32)
    content_hash: str | None = Field(default=None, max_length=64)


class SitrepBody(BaseModel):
    current_status: str = Field(default="", max_length=2000)
    what_changed: str = Field(default="", max_length=2000)
    business_services: str = Field(default="", max_length=2000)
    known_facts: str = Field(default="", max_length=4000)
    uncertain_facts: str = Field(default="", max_length=4000)
    actions_and_owners: str = Field(default="", max_length=4000)
    decisions_required: str = Field(default="", max_length=2000)
    evidence_freshness: str = Field(default="", max_length=1000)
    external_communication_state: str = Field(default="", max_length=500)
    regulatory_assessment_state: str = Field(default="", max_length=500)


class CommDraftBody(BaseModel):
    template_key: str = Field(max_length=64)
    subject: str = Field(default="", max_length=300)
    body_text: str = Field(default="", max_length=8000)


class RegulatoryBody(BaseModel):
    profile_id: uuid.UUID
    legal_applicability: str = Field(default="not_determined", max_length=32)
    reporting_obligation: str = Field(default="not_determined", max_length=32)
    deadline_hours_confirmed: int | None = Field(default=None, ge=1, le=8760)
    confirm_deadline: bool = False
    liaison_confirmed: bool = False
    liaison_identity_id: uuid.UUID | None = None
    evidence_notes: str = Field(default="", max_length=4000)
    expected_version: int | None = None


class SnapshotBody(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=200)


class CloseBody(BaseModel):
    notes: str = Field(min_length=1, max_length=4000)
    lessons_learned: str = Field(default="", max_length=4000)
    expected_version: int | None = None


class ReopenBody(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    expected_version: int | None = None


class CancelBody(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    expected_version: int | None = None


class IntelLinkBody(BaseModel):
    link_type: str = Field(min_length=1, max_length=64)
    target_id: uuid.UUID
    label: str = Field(default="", max_length=300)
    evidence_assessment: str = Field(default="unreviewed", max_length=32)
    notes: str = Field(default="", max_length=1000)


@router.get("/summary")
def summary(workspace: WorkspaceScope, db: DbSession) -> dict:
    return response_service.command_center_summary(db, workspace.tenant_id, workspace.id)


@router.get("")
def list_responses(
    workspace: WorkspaceScope,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    mode: str | None = None,
    lifecycle: str | None = None,
) -> dict:
    return response_service.list_responses(
        db, workspace.tenant_id, workspace.id, limit=limit, offset=offset, mode=mode, lifecycle=lifecycle
    )


@router.post("/propose")
def propose(body: ProposeBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.propose(
        db,
        workspace.tenant_id,
        workspace.id,
        actor=actor,
        role=workspace.role,
        title=body.title,
        reason=body.reason,
        mode=body.mode,
        stable_key=body.stable_key,
        idempotency_key=body.idempotency_key,
        known_facts=body.known_facts,
        uncertain_facts=body.uncertain_facts,
        operational_impact=body.operational_impact,
        is_synthetic=body.is_synthetic,
        services=body.services,
    )
    db.commit()
    return result


@router.get("/jurisdiction-profiles")
def jurisdiction_profiles(workspace: WorkspaceScope, db: DbSession) -> dict:
    return response_service.list_jurisdiction_profiles(db)


@router.get("/{response_id}")
def get_response(response_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = response_service._get(db, workspace.tenant_id, workspace.id, response_id)
    return response_service.serialize_detail(db, row)


@router.post("/{response_id}/activate")
def activate(response_id: uuid.UUID, body: ActivateBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.activate(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        rationale=body.rationale,
        expected_version=body.expected_version,
        mode=body.mode,
    )
    db.commit()
    return result


@router.post("/{response_id}/declaration")
def declaration(response_id: uuid.UUID, body: DeclarationBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.change_declaration(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        declaration_state=body.declaration_state,
        rationale=body.rationale,
        remaining_uncertainty=body.remaining_uncertainty,
        expected_version=body.expected_version,
        evidence_reviewed=body.evidence_reviewed,
    )
    db.commit()
    return result


@router.post("/{response_id}/roles")
def assign_role(response_id: uuid.UUID, body: RoleBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.assign_role(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        role_key=body.role_key,
        identity_id=body.identity_id,
        notes=body.notes,
    )
    db.commit()
    return result


@router.post("/{response_id}/actions")
def link_action(response_id: uuid.UUID, body: ActionLinkBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.link_action(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        action_id=body.action_id,
        response_role=body.response_role,
        notes=body.notes,
    )
    db.commit()
    return result


@router.delete("/{response_id}/actions/{action_id}")
def unlink_action(
    response_id: uuid.UUID, action_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor
) -> dict:
    result = response_service.unlink_action(
        db, workspace.tenant_id, workspace.id, response_id, action_id, actor=actor, role=workspace.role
    )
    db.commit()
    return result


@router.post("/{response_id}/timeline")
def add_timeline(response_id: uuid.UUID, body: TimelineBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.add_timeline_entry(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        category=body.category,
        summary=body.summary,
        evidence_state=body.evidence_state,
        event_time=body.event_time,
    )
    db.commit()
    return result


@router.post("/{response_id}/timeline/{entry_id}/correct")
def correct_timeline(
    response_id: uuid.UUID,
    entry_id: uuid.UUID,
    body: TimelineCorrectBody,
    workspace: WorkspaceScope,
    db: DbSession,
    actor: Actor,
) -> dict:
    result = response_service.correct_timeline_entry(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        entry_id,
        actor=actor,
        role=workspace.role,
        summary=body.summary,
        category=body.category,
        evidence_state=body.evidence_state,
    )
    db.commit()
    return result


@router.post("/{response_id}/decisions")
def add_decision(response_id: uuid.UUID, body: DecisionBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.add_decision(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        decision=body.decision,
        rationale=body.rationale,
        evidence_considered=body.evidence_considered,
        alternatives=body.alternatives,
        remaining_uncertainty=body.remaining_uncertainty,
        idempotency_key=body.idempotency_key,
        review_at=body.review_at,
    )
    db.commit()
    return result


@router.post("/{response_id}/evidence")
def pin_evidence(response_id: uuid.UUID, body: EvidencePinBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.pin_evidence(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        ref_kind=body.ref_kind,
        ref_id=body.ref_id,
        label=body.label,
        evidence_assessment=body.evidence_assessment,
        content_hash=body.content_hash,
    )
    db.commit()
    return result


@router.post("/{response_id}/intelligence")
def link_intel(response_id: uuid.UUID, body: IntelLinkBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.link_intelligence(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        link_type=body.link_type,
        target_id=body.target_id,
        label=body.label,
        evidence_assessment=body.evidence_assessment,
        notes=body.notes,
    )
    db.commit()
    return result


@router.post("/{response_id}/situation-reports")
def create_sitrep(response_id: uuid.UUID, body: SitrepBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.create_sitrep(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        fields=body.model_dump(),
    )
    db.commit()
    return result


@router.post("/{response_id}/situation-reports/{report_id}/finalize")
def finalize_sitrep(
    response_id: uuid.UUID, report_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor
) -> dict:
    result = response_service.finalize_sitrep(
        db, workspace.tenant_id, workspace.id, response_id, report_id, actor=actor, role=workspace.role
    )
    db.commit()
    return result


@router.get("/{response_id}/situation-reports/{report_id}")
def get_sitrep(response_id: uuid.UUID, report_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = response_service._get(db, workspace.tenant_id, workspace.id, response_id)
    report = db.scalar(
        select(ResponseSituationReport).where(
            ResponseSituationReport.id == report_id,
            ResponseSituationReport.response_id == row.id,
            ResponseSituationReport.workspace_id == workspace.id,
        )
    )
    if report is None:
        raise HTTPException(status_code=404, detail="Not found")
    return response_service._sitrep_out(report, row)


@router.post("/{response_id}/communications")
def create_comm(response_id: uuid.UUID, body: CommDraftBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.create_comm_draft(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        template_key=body.template_key,
        subject=body.subject,
        body_text=body.body_text,
    )
    db.commit()
    return result


@router.post("/{response_id}/communications/{draft_id}/approve")
def approve_comm(
    response_id: uuid.UUID, draft_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor
) -> dict:
    result = response_service.approve_comm_draft(
        db, workspace.tenant_id, workspace.id, response_id, draft_id, actor=actor, role=workspace.role
    )
    db.commit()
    return result


@router.put("/{response_id}/regulatory")
def regulatory(response_id: uuid.UUID, body: RegulatoryBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.upsert_regulatory(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        profile_id=body.profile_id,
        legal_applicability=body.legal_applicability,
        reporting_obligation=body.reporting_obligation,
        deadline_hours_confirmed=body.deadline_hours_confirmed,
        confirm_deadline=body.confirm_deadline,
        liaison_confirmed=body.liaison_confirmed,
        liaison_identity_id=body.liaison_identity_id,
        evidence_notes=body.evidence_notes,
        expected_version=body.expected_version,
    )
    db.commit()
    return result


@router.post("/{response_id}/snapshots")
def create_snapshot(response_id: uuid.UUID, body: SnapshotBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.create_snapshot(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        idempotency_key=body.idempotency_key,
    )
    db.commit()
    return result


@router.get("/{response_id}/snapshots/{snapshot_id}")
def get_snapshot(response_id: uuid.UUID, snapshot_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = response_service._get(db, workspace.tenant_id, workspace.id, response_id)
    snap = db.scalar(
        select(ResponseSnapshot).where(
            ResponseSnapshot.id == snapshot_id,
            ResponseSnapshot.response_id == row.id,
            ResponseSnapshot.workspace_id == workspace.id,
        )
    )
    if snap is None:
        raise HTTPException(status_code=404, detail="Not found")
    from threatsight_api.response.snapshots import _out

    return _out(db, snap)


@router.post("/{response_id}/close")
def close_response(response_id: uuid.UUID, body: CloseBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.close_response(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        notes=body.notes,
        lessons_learned=body.lessons_learned,
        expected_version=body.expected_version,
    )
    db.commit()
    return result


@router.post("/{response_id}/reopen")
def reopen_response(response_id: uuid.UUID, body: ReopenBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.reopen_response(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        reason=body.reason,
        expected_version=body.expected_version,
    )
    db.commit()
    return result


@router.post("/{response_id}/cancel")
def cancel_response(response_id: uuid.UUID, body: CancelBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = response_service.cancel_response(
        db,
        workspace.tenant_id,
        workspace.id,
        response_id,
        actor=actor,
        role=workspace.role,
        reason=body.reason,
        expected_version=body.expected_version,
    )
    db.commit()
    return result
