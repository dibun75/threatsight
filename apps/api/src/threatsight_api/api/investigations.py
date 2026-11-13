"""Read-only investigation chain. The route does not create relationships."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.investigations.read import path, service

router = APIRouter(prefix="/investigations", tags=["investigations"])
_NOT_FOUND = "Investigation not found"


@router.get("/services/{service_id}")
def get_service(service_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = service(db, workspace.tenant_id, workspace.id, service_id)
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


@router.get("/paths/{result_id}")
def get_path(result_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = path(db, workspace.tenant_id, workspace.id, result_id)
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row
