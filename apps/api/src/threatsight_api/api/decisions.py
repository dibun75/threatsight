"""Read-only service decisions. The route does not mutate or score."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.decisions.read import one, services

router = APIRouter(prefix="/decisions", tags=["decisions"])
_NOT_FOUND = "Decision not found"


@router.get("/services")
def list_decisions(workspace: WorkspaceScope, db: DbSession) -> dict:
    return services(db, workspace.tenant_id, workspace.id)


@router.get("/services/{service_id}")
def get_decision(service_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = one(db, workspace.tenant_id, workspace.id, service_id)
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row
