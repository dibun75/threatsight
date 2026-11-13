"""Local sign-in and owner account administration."""

from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from threatsight_api.api.deps import DbSession
from threatsight_api.config import get_settings
from threatsight_api.local_auth.service import (
    LocalAuthError,
    account_in_tenant,
    assign_role,
    authenticate,
    consume_token,
    issue_token,
    revoke_sessions,
    revoke_token,
    set_enabled,
)
from threatsight_api.oidc import CSRF_COOKIE, SESSION_COOKIE, browser_cookie_name, expire_browser_cookies
from threatsight_api.persistence.models import LocalCredential, TenantMembership, Workspace

router = APIRouter(prefix="/auth/local", tags=["local-auth"])


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class Activation(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=1, max_length=128)


class Invite(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: str = Field(min_length=3, max_length=32)


class AccountChange(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    enabled: bool | None = None
    role: str | None = Field(default=None, max_length=32)


def _client_source(request: Request) -> str:
    return (request.client.host if request.client else "unknown")[:80]


def _cookies(response: JSONResponse, opaque: str) -> None:
    settings = get_settings()
    secure = settings.is_production
    max_age = settings.auth_session_minutes * 60
    expire_browser_cookies(response)
    response.set_cookie(
        f"__Host-{SESSION_COOKIE}" if secure else SESSION_COOKIE,
        opaque,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        browser_cookie_name(CSRF_COOKIE, secure=secure),
        secrets.token_urlsafe(32),
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="lax",
        path="/",
    )


def _owner(request: Request) -> uuid.UUID:
    if getattr(request.state, "role", "") != "platform-admin":
        raise HTTPException(status_code=403, detail="Role is read-only")
    tenant_id = getattr(request.state, "tenant_id", None)
    identity_id = getattr(request.state, "identity_id", None)
    if tenant_id is None or identity_id is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return uuid.UUID(str(identity_id))


def _map(exc: LocalAuthError) -> HTTPException:
    headers = {"Retry-After": "30"} if exc.status == 429 else None
    return HTTPException(status_code=exc.status, detail=exc.detail, headers=headers)


@router.post("/login")
def login(body: Credentials, request: Request, db: DbSession):
    if get_settings().normalized_auth_mode != "local":
        raise HTTPException(status_code=404, detail="Local authentication is not enabled")
    try:
        _identity, opaque = authenticate(db, email=body.email, password=body.password, source=_client_source(request))
    except LocalAuthError as exc:
        db.commit()
        raise _map(exc) from exc
    db.commit()
    response = JSONResponse({"ok": True})
    _cookies(response, opaque)
    return response


@router.post("/activate")
def activate(body: Activation, db: DbSession):
    try:
        consume_token(db, raw=body.token, password=body.password, purpose="activation")
    except LocalAuthError as exc:
        raise _map(exc) from exc
    db.commit()
    return {"ok": True}


@router.post("/reset")
def reset(body: Activation, db: DbSession):
    try:
        consume_token(db, raw=body.token, password=body.password, purpose="reset")
    except LocalAuthError as exc:
        raise _map(exc) from exc
    db.commit()
    return {"ok": True}


@router.get("/accounts")
def accounts(request: Request, db: DbSession):
    identity_id = _owner(request)
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    del identity_id
    rows = db.execute(
        select(LocalCredential, TenantMembership.role)
        .join(TenantMembership, TenantMembership.identity_id == LocalCredential.identity_id)
        .where(TenantMembership.tenant_id == tenant_id)
        .order_by(LocalCredential.email)
    ).all()
    return {"items": [{"email": credential.email, "enabled": credential.enabled, "role": role} for credential, role in rows]}


@router.post("/accounts")
def invite(body: Invite, request: Request, db: DbSession):
    actor_id = _owner(request)
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    workspace = db.scalar(select(Workspace).where(Workspace.tenant_id == tenant_id, Workspace.status == "active"))
    if workspace is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    if account_in_tenant(db, email=body.email, tenant_id=tenant_id) is not None:
        raise HTTPException(status_code=409, detail="Account already exists.")
    try:
        raw = issue_token(
            db,
            email=body.email,
            role=body.role,
            tenant_id=tenant_id,
            workspace_id=workspace.id,
            purpose="activation",
            issuer_id=actor_id,
        )
    except LocalAuthError as exc:
        raise _map(exc) from exc
    db.commit()
    return {"token": raw}


@router.post("/accounts/change")
def change(body: AccountChange, request: Request, db: DbSession):
    actor_id = _owner(request)
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    try:
        if body.enabled is not None:
            set_enabled(db, actor_id=actor_id, tenant_id=tenant_id, email=body.email, enabled=body.enabled)
        if body.role is not None:
            assign_role(db, actor_id=actor_id, tenant_id=tenant_id, email=body.email, role=body.role)
    except LocalAuthError as exc:
        raise _map(exc) from exc
    db.commit()
    return {"ok": True}


@router.post("/accounts/reset")
def reset_link(body: Invite, request: Request, db: DbSession):
    actor_id = _owner(request)
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    found = account_in_tenant(db, email=body.email, tenant_id=tenant_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    credential, _membership = found
    try:
        raw = issue_token(
            db,
            email=credential.email,
            role=_membership.role,
            tenant_id=tenant_id,
            workspace_id=db.scalar(select(Workspace.id).where(Workspace.tenant_id == tenant_id)),
            purpose="reset",
            issuer_id=actor_id,
        )
    except LocalAuthError as exc:
        raise _map(exc) from exc
    db.commit()
    return {"token": raw}


@router.post("/accounts/revoke-sessions")
def revoke(body: Invite, request: Request, db: DbSession):
    _owner(request)
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    found = account_in_tenant(db, email=body.email, tenant_id=tenant_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    credential, _membership = found
    count = revoke_sessions(db, credential.identity_id)
    db.commit()
    return {"revoked": count}


@router.post("/tokens/{token_id}/revoke")
def revoke_invite(token_id: uuid.UUID, request: Request, db: DbSession):
    _owner(request)
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    try:
        revoke_token(db, token_id=token_id, tenant_id=tenant_id)
    except LocalAuthError as exc:
        raise _map(exc) from exc
    db.commit()
    return {"ok": True}
