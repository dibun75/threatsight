"""Workspace-scoped accountable readiness-action APIs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, Field

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, WorkspaceScope
from threatsight_api.readiness import actions as action_service

router = APIRouter(prefix="/readiness/actions", tags=["readiness-actions"])


class AssignBody(BaseModel):
    owner_identity_id: uuid.UUID | None = None
    due_at: datetime | None = None
    expected_version: int | None = Field(default=None, ge=1)


class TransitionBody(BaseModel):
    status: Literal["open", "assigned", "in_progress", "awaiting_evidence", "ready_for_review", "reopened", "superseded", "cancelled"]
    rationale: str = Field(default="", max_length=1000)
    expected_version: int | None = Field(default=None, ge=1)


class SatisfyBody(BaseModel):
    evidence_id: uuid.UUID | None = None


class CloseBody(BaseModel):
    outcome: Literal["resolved_by_evidence", "remediation_completed", "not_applicable", "risk_accepted", "superseded"]
    rationale: str = Field(min_length=1, max_length=1000)
    expected_version: int | None = Field(default=None, ge=1)
    risk_accepted_until: datetime | None = None
    risk_scope: str | None = Field(default=None, max_length=500)


class ReopenBody(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    expected_version: int | None = Field(default=None, ge=1)
    new_evidence_hash: str | None = Field(default=None, max_length=64)


@router.get("/summary")
def action_summary(workspace: WorkspaceScope, db: DbSession) -> dict:
    return action_service.summary(db, workspace.tenant_id, workspace.id)


@router.get("")
def list_actions(
    workspace: WorkspaceScope,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    status: Annotated[str | None, Query(max_length=32)] = None,
    service: Annotated[str | None, Query(max_length=500)] = None,
    owner: Annotated[str | None, Query(max_length=200)] = None,
    due: Annotated[str | None, Query(max_length=32)] = None,
) -> dict:
    return action_service.list_actions(
        db,
        workspace.tenant_id,
        workspace.id,
        status=status,
        service=service,
        owner=owner,
        due=due,
        limit=limit,
        offset=offset,
    )


@router.get("/{action_id}")
def get_action(action_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    return action_service.get_action(db, workspace.tenant_id, workspace.id, action_id)


@router.post("/{action_id}/assign")
def assign_action(action_id: uuid.UUID, body: AssignBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = action_service.assign(
        db,
        workspace.tenant_id,
        workspace.id,
        action_id,
        body.owner_identity_id,
        actor,
        workspace.role,
        due_at=body.due_at,
        expected_version=body.expected_version,
    )
    db.commit()
    return result


@router.post("/{action_id}/transition")
def transition_action(action_id: uuid.UUID, body: TransitionBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = action_service.transition(
        db,
        workspace.tenant_id,
        workspace.id,
        action_id,
        body.status,
        actor,
        workspace.role,
        rationale=body.rationale,
        expected_version=body.expected_version,
    )
    db.commit()
    return result


@router.post("/{action_id}/requirements/{requirement_id}/satisfy")
def satisfy_requirement(
    action_id: uuid.UUID,
    requirement_id: uuid.UUID,
    body: SatisfyBody,
    workspace: WorkspaceScope,
    db: DbSession,
    actor: Actor,
) -> dict:
    result = action_service.satisfy_requirement(
        db,
        workspace.tenant_id,
        workspace.id,
        action_id,
        requirement_id,
        actor,
        workspace.role,
        evidence_id=body.evidence_id,
    )
    db.commit()
    return result


@router.post("/{action_id}/close")
def close_action(action_id: uuid.UUID, body: CloseBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = action_service.close(
        db,
        workspace.tenant_id,
        workspace.id,
        action_id,
        body.outcome,
        body.rationale,
        actor,
        workspace.role,
        expected_version=body.expected_version,
        risk_accepted_until=body.risk_accepted_until,
        risk_scope=body.risk_scope,
    )
    db.commit()
    return result


@router.post("/{action_id}/reopen")
def reopen_action(action_id: uuid.UUID, body: ReopenBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = action_service.reopen(
        db,
        workspace.tenant_id,
        workspace.id,
        action_id,
        body.reason,
        actor,
        workspace.role,
        expected_version=body.expected_version,
        new_evidence_hash=body.new_evidence_hash,
    )
    db.commit()
    return result


@router.get("/{action_id}/manifest")
def preview_manifest(action_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    return action_service.preview_manifest(db, workspace.tenant_id, workspace.id, action_id)


@router.post("/{action_id}/manifest/download")
def download_manifest(action_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor, response: Response) -> dict:
    body = action_service.download_manifest(db, workspace.tenant_id, workspace.id, action_id, actor)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Disposition"] = f'attachment; filename="{body["filename"]}"'
    return body
