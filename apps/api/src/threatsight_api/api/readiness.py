"""Workspace-scoped continuous readiness APIs."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, WorkspaceScope
from threatsight_api.readiness import service as readiness

router = APIRouter(prefix="/readiness", tags=["readiness"])


class DecisionBody(BaseModel):
    outcome: Literal["accepted", "remediation_required", "not_applicable", "needs_more_data", "risk_accepted", "superseded"]
    rationale: str = Field(min_length=1, max_length=1000)


@router.get("/summary")
def readiness_summary(workspace: WorkspaceScope, db: DbSession) -> dict:
    return readiness.summary(db, workspace.tenant_id, workspace.id)


@router.get("/recommendations")
def list_recommendations(
    workspace: WorkspaceScope,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    state: Annotated[str | None, Query(max_length=32)] = None,
    service: Annotated[str | None, Query(max_length=500)] = None,
) -> dict:
    return readiness.list_recommendations(db, workspace.tenant_id, workspace.id, state=state, service=service, limit=limit, offset=offset)


@router.get("/recommendations/{recommendation_id}")
def get_recommendation(recommendation_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    return readiness.get_recommendation(db, workspace.tenant_id, workspace.id, recommendation_id)


@router.post("/recommendations/{recommendation_id}/preview")
def preview_recommendation(recommendation_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    return readiness.preview(db, workspace.tenant_id, workspace.id, recommendation_id, actor, workspace.role)


@router.post("/recommendations/{recommendation_id}/approve")
def approve_recommendation(recommendation_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    body = readiness.approve(db, workspace.tenant_id, workspace.id, recommendation_id, actor, workspace.role)
    db.commit()
    return body


@router.post("/recommendations/{recommendation_id}/dismiss")
def dismiss_recommendation(recommendation_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    body = readiness.dismiss(db, workspace.tenant_id, workspace.id, recommendation_id, actor, workspace.role)
    db.commit()
    return body


@router.get("/requests")
def list_requests(
    workspace: WorkspaceScope,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    service: Annotated[str | None, Query(max_length=500)] = None,
) -> dict:
    return readiness.list_requests(db, workspace.tenant_id, workspace.id, service=service, limit=limit, offset=offset)


@router.get("/requests/{request_id}")
def get_request(request_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    return readiness.get_request(db, workspace.tenant_id, workspace.id, request_id)


@router.post("/requests/{request_id}/decisions")
def create_decision(request_id: uuid.UUID, body: DecisionBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = readiness.decide(db, workspace.tenant_id, workspace.id, request_id, body.outcome, body.rationale, actor, workspace.role)
    db.commit()
    return result


@router.post("/engine/run")
def run_engine(workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    if workspace.role not in {"workspace-admin", "platform-admin", "admin", "operator"}:
        raise HTTPException(status_code=403, detail="Operator permission required")
    from threatsight_api.readiness.engine import recommend_for_workspace

    body = recommend_for_workspace(db, workspace.tenant_id, workspace.id, actor=actor)
    db.commit()
    return body
