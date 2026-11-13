from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.session import get_db
from threatsight_api.config import get_settings
from threatsight_api.oidc import canonical_role
from threatsight_api.persistence.models import Workspace, WorkspaceMembership


def get_actor(request: Request) -> str:
    value = str(getattr(request.state, "actor", "")).strip()
    if not value or len(value) > 200:
        raise HTTPException(status_code=401, detail="Authenticated actor is required")
    return value


@dataclass(frozen=True)
class WorkspaceContext:
    id: uuid.UUID
    tenant_id: uuid.UUID
    key: str
    subject: str
    role: str


def tenant_matches(authenticated_tenant: object | None, workspace_tenant: object) -> bool:
    return authenticated_tenant is None or str(authenticated_tenant) == str(workspace_tenant)


def get_workspace_context(
    request: Request,
    session: Session = Depends(get_db),
    x_workspace_key: Annotated[str | None, Header(alias="X-Workspace-Key")] = None,
) -> WorkspaceContext:
    settings = get_settings()
    public_demo = settings.normalized_auth_mode == "public_demo"
    key = settings.public_demo_workspace_key if public_demo else (x_workspace_key or settings.default_workspace_key)
    key = key.strip().lower()
    if not key or len(key) > 64:
        raise HTTPException(status_code=400, detail="Invalid workspace key")
    subject = settings.public_demo_subject.strip() if public_demo else str(getattr(request.state, "actor", "")).strip()
    workspace = session.scalar(select(Workspace).where(Workspace.key == key, Workspace.status == "active"))
    if workspace is None:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    authenticated_tenant = getattr(request.state, "tenant_id", None)
    if not tenant_matches(authenticated_tenant, workspace.tenant_id):
        raise HTTPException(status_code=403, detail="Workspace access denied")
    identity_id = getattr(request.state, "identity_id", None)
    membership_predicate = (
        WorkspaceMembership.identity_id == uuid.UUID(str(identity_id))
        if identity_id is not None
        else WorkspaceMembership.subject == subject
    )
    membership = session.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace.id,
            membership_predicate,
        )
    )
    if membership is None:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    role = "viewer" if public_demo else canonical_role(membership.role)
    if getattr(request.state, "via_api_token", False):
        role = "auditor"  # API tokens are read-only whatever the identity's own role
    if public_demo and workspace.classification != "synthetic_demo":
        raise HTTPException(status_code=403, detail="Workspace access denied")
    return WorkspaceContext(
        id=workspace.id,
        tenant_id=workspace.tenant_id,
        key=workspace.key,
        subject=subject,
        role=role,
    )

WorkspaceScope = Annotated[WorkspaceContext, Depends(get_workspace_context)]
Actor = Annotated[str, Depends(get_actor)]
DbSession = Annotated[Session, Depends(get_db)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=100000)]


def require_entity(session: Session, model: type, entity_id: uuid.UUID, label: str):
    obj = session.get(model, entity_id)
    if obj is None:
        raise HTTPException(status_code=404, detail=f"{label} not found")
    return obj
