"""Read-only API tokens and alert destinations. Administrators only."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.integrations import alerts, tokens
from threatsight_api.persistence.integration_models import AlertDelivery, AlertDestination, ApiToken
from threatsight_api.persistence.models import Identity, TenantMembership
from threatsight_api.services.audit import record_audit

router = APIRouter(tags=["integrations"])
ADMIN_ROLES = frozenset({"workspace-admin", "platform-admin"})


def _owner(request: Request) -> tuple[uuid.UUID, uuid.UUID, str]:
    """(tenant, identity, actor) of a signed-in platform administrator. Tokens never qualify."""
    if getattr(request.state, "role", "") != "platform-admin" or getattr(request.state, "via_api_token", False):
        raise HTTPException(status_code=403, detail="Only a platform administrator can manage API tokens")
    tenant_id = getattr(request.state, "tenant_id", None)
    identity_id = getattr(request.state, "identity_id", None)
    if tenant_id is None or identity_id is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return uuid.UUID(str(tenant_id)), uuid.UUID(str(identity_id)), str(getattr(request.state, "actor", ""))


# API tokens -----------------------------------------------------------------------------------

class TokenBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    identity_id: uuid.UUID | None = None


def token_view(row: ApiToken, identity: Identity | None) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "name": row.name,
        "prefix": f"{tokens.PREFIX}{row.prefix}_…",
        "identity": {"id": str(row.identity_id), "name": identity.display_name if identity else None, "email": identity.email if identity else None},
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
    }


@router.get("/auth/token")
def token_whoami(request: Request) -> dict:
    """Who the API token in the Authorization header belongs to."""
    if not getattr(request.state, "via_api_token", False):
        raise HTTPException(status_code=401, detail="Send a valid API token as 'Authorization: Bearer tsk_…'")
    return {"actor": request.state.actor, "role": request.state.role, "token": request.state.api_token, "read_only": True}


@router.get("/auth/tokens")
def list_tokens(request: Request, db: DbSession) -> dict:
    tenant_id, _identity, _actor = _owner(request)
    rows = db.execute(
        select(ApiToken, Identity).join(Identity, Identity.id == ApiToken.identity_id).where(ApiToken.tenant_id == tenant_id).order_by(ApiToken.created_at.desc())
    ).all()
    return {"items": [token_view(t, i) for t, i in rows]}


@router.post("/auth/tokens", status_code=201)
def create_token(body: TokenBody, request: Request, db: DbSession) -> dict:
    tenant_id, own_identity, actor = _owner(request)
    identity_id = body.identity_id or own_identity
    member = db.scalar(select(TenantMembership).where(TenantMembership.tenant_id == tenant_id, TenantMembership.identity_id == identity_id))
    identity = db.get(Identity, identity_id)
    if member is None or identity is None or identity.status != "active":
        raise HTTPException(status_code=400, detail="Tokens can only be issued to an active member of this tenant")
    token, prefix, digest = tokens.new_token()
    row = ApiToken(tenant_id=tenant_id, identity_id=identity_id, name=body.name.strip(), prefix=prefix, token_hash=digest, created_by=actor)
    db.add(row)
    db.flush()
    record_audit(db, entity_type="api_token", entity_id=row.id, action="created", actor=actor, payload={"name": row.name})
    db.commit()
    return {**token_view(row, identity), "token": token}


@router.delete("/auth/tokens/{token_id}")
def revoke_token(token_id: uuid.UUID, request: Request, db: DbSession) -> dict:
    tenant_id, _identity, actor = _owner(request)
    row = db.get(ApiToken, token_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="No such token")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        record_audit(db, entity_type="api_token", entity_id=row.id, action="revoked", actor=actor, payload={"name": row.name})
        db.commit()
    tokens.forget(token_id)
    return token_view(row, db.get(Identity, row.identity_id))


# Alert destinations ---------------------------------------------------------------------------

def _admin(workspace: WorkspaceScope, request: Request) -> None:
    if workspace.role not in ADMIN_ROLES or getattr(request.state, "via_api_token", False):
        raise HTTPException(status_code=403, detail="Only an administrator can see or change alert destinations")


def _destination(db, workspace: WorkspaceScope, destination_id: uuid.UUID) -> AlertDestination:
    row = db.get(AlertDestination, destination_id)
    if row is None or row.workspace_id != workspace.id or row.tenant_id != workspace.tenant_id:
        raise HTTPException(status_code=404, detail="No such destination")
    return row


class DestinationBody(BaseModel):
    kind: str = Field(max_length=16)
    label: str = Field(max_length=80)
    url: str | None = Field(default=None, max_length=1000)
    secret: str | None = Field(default=None, max_length=200)
    host: str | None = Field(default=None, max_length=253)
    port: int | None = None
    protocol: str | None = Field(default=None, max_length=8)


class EnabledBody(BaseModel):
    enabled: bool


@router.get("/integrations/alerts")
def alert_overview(workspace: WorkspaceScope, request: Request, db: DbSession) -> dict:
    _admin(workspace, request)
    destinations = db.scalars(
        select(AlertDestination).where(AlertDestination.workspace_id == workspace.id).order_by(AlertDestination.created_at)
    ).all()
    deliveries = db.scalars(
        select(AlertDelivery).where(AlertDelivery.workspace_id == workspace.id).order_by(AlertDelivery.created_at.desc()).limit(50)
    ).all()
    return {
        "destinations": [alerts.public_view(d) for d in destinations],
        "deliveries": [
            {"time": d.created_at.isoformat(), "event": d.event_type, "subject": d.subject, "destination": d.destination_label,
             "kind": d.kind, "ok": d.ok, "error": d.error}
            for d in deliveries
        ],
        "fires_on": sorted(alerts.ALERT_OUTCOMES),
    }


@router.post("/integrations/alerts/destinations", status_code=201)
def add_destination(body: DestinationBody, workspace: WorkspaceScope, request: Request, db: DbSession) -> dict:
    _admin(workspace, request)
    try:
        values = alerts.validate(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    count = db.scalar(select(func.count()).select_from(AlertDestination).where(AlertDestination.workspace_id == workspace.id)) or 0
    if count >= alerts.MAX_DESTINATIONS:
        raise HTTPException(status_code=400, detail=f"At most {alerts.MAX_DESTINATIONS} destinations; remove one first")
    row = AlertDestination(tenant_id=workspace.tenant_id, workspace_id=workspace.id, created_by=workspace.subject, **values)
    db.add(row)
    db.flush()
    record_audit(db, entity_type="alert_destination", entity_id=row.id, action="created", actor=workspace.subject, payload={"kind": row.kind, "label": row.label})
    db.commit()
    return alerts.public_view(row)


@router.patch("/integrations/alerts/destinations/{destination_id}")
def set_enabled(destination_id: uuid.UUID, body: EnabledBody, workspace: WorkspaceScope, request: Request, db: DbSession) -> dict:
    _admin(workspace, request)
    row = _destination(db, workspace, destination_id)
    row.enabled = body.enabled
    record_audit(db, entity_type="alert_destination", entity_id=row.id, action="enabled" if body.enabled else "disabled", actor=workspace.subject, payload={})
    db.commit()
    return alerts.public_view(row)


@router.delete("/integrations/alerts/destinations/{destination_id}")
def remove_destination(destination_id: uuid.UUID, workspace: WorkspaceScope, request: Request, db: DbSession) -> dict:
    _admin(workspace, request)
    row = _destination(db, workspace, destination_id)
    record_audit(db, entity_type="alert_destination", entity_id=row.id, action="deleted", actor=workspace.subject, payload={"label": row.label})
    db.delete(row)
    db.commit()
    return {"deleted": True}


@router.post("/integrations/alerts/destinations/{destination_id}/test")
def test_destination(destination_id: uuid.UUID, workspace: WorkspaceScope, request: Request, db: DbSession) -> dict:
    _admin(workspace, request)
    row = _destination(db, workspace, destination_id)
    return alerts.attempt(alerts.Target.of(row), alerts.ping_event(), tries=1)
