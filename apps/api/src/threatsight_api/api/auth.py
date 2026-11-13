from __future__ import annotations

import json
import secrets
import urllib.parse
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy import select

from threatsight_api.access import safe_return_path
from threatsight_api.api.deps import DbSession
from threatsight_api.config import get_settings
from threatsight_api.oidc import (
    CSRF_COOKIE,
    FLOW_COOKIE,
    OIDCValidationError,
    SESSION_COOKIE,
    browser_cookie_name,
    create_session,
    expire_browser_cookies,
    hash_opaque,
    presented_session_tokens,
    load_jwks,
    pkce_challenge,
    role_from_claims,
    validate_id_token,
)
from threatsight_api.url_safety import open_unredirected
from threatsight_api.services.audit import record_audit
from threatsight_api.persistence.models import (
    AuthSession,
    Identity,
    OIDCAuthFlow,
    Tenant,
    TenantMembership,
    Workspace,
    WorkspaceMembership,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def flow_is_usable(flow: OIDCAuthFlow | None, now: datetime) -> bool:
    return flow is not None and flow.consumed_at is None and flow.expires_at > now


def _require_oidc() -> None:
    if get_settings().normalized_auth_mode != "oidc":
        raise HTTPException(status_code=404, detail="OIDC authentication is not enabled")


def _oidc_configured(settings) -> bool:
    return all(
        value.strip()
        for value in (
            settings.oidc_issuer,
            settings.oidc_client_id,
            settings.oidc_authorization_endpoint,
            settings.oidc_token_endpoint,
            settings.oidc_jwks_uri,
            settings.oidc_redirect_uri,
        )
    )


@router.get("/status")
def status() -> dict:
    settings = get_settings()
    configured = settings.normalized_auth_mode == "oidc" and _oidc_configured(settings)
    return {
        "mode": settings.normalized_auth_mode,
        "oidc_configured": configured,
        "sign_in_available": configured,
        "detail": "Sign in with Microsoft is available." if configured else "Production identity has not been configured.",
    }


@router.get("/login")
def login(db: DbSession, return_to: str = Query(default="/demo", max_length=500)):
    _require_oidc()
    settings = get_settings()
    try:
        return_to = safe_return_path(return_to)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid return path") from exc
    state, nonce, verifier, binding = (
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(64),
        secrets.token_urlsafe(32),
    )
    db.add(
        OIDCAuthFlow(
            state_hash=hash_opaque(f"{state}.{binding}"),
            nonce=nonce,
            code_verifier=verifier,
            return_to=return_to,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
    )
    query = urllib.parse.urlencode(
        {
            "client_id": settings.oidc_client_id,
            "response_type": "code",
            "redirect_uri": settings.oidc_redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
    )
    response = RedirectResponse(f"{settings.oidc_authorization_endpoint}?{query}", status_code=302)
    _set_cookie(response, settings, FLOW_COOKIE, binding, httponly=True, max_age=600)
    return response


def _exchange_code(code: str, verifier: str) -> str:
    settings = get_settings()
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_redirect_uri,
        "client_id": settings.oidc_client_id,
        "code_verifier": verifier,
    }
    if settings.oidc_client_secret:
        form["client_secret"] = settings.oidc_client_secret
    try:
        with open_unredirected(
            settings.oidc_token_endpoint,
            data=urllib.parse.urlencode(form).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
            production=settings.is_production,
        ) as response:
            payload = response.read(1_048_577)
    except Exception as exc:
        raise OIDCValidationError("token exchange failed") from exc
    if len(payload) > 1_048_576:
        raise OIDCValidationError("token response too large")
    try:
        body = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise OIDCValidationError("invalid token response") from exc
    if not isinstance(body, dict) or not isinstance(body.get("id_token"), str):
        raise OIDCValidationError("ID token missing")
    return body["id_token"]


def _flow_binding(request: Request) -> str:
    return (
        request.cookies.get(browser_cookie_name(FLOW_COOKIE, secure=True))
        or request.cookies.get(browser_cookie_name(FLOW_COOKIE, secure=False))
        or ""
    )


@router.get("/callback")
def callback(
    request: Request,
    db: DbSession,
    state: str = Query(min_length=20, max_length=200),
    code: str = Query(min_length=1, max_length=4000),
):
    _require_oidc()
    settings = get_settings()
    binding = _flow_binding(request)
    if not binding:
        raise HTTPException(status_code=401, detail="Invalid or expired authentication state")
    now = datetime.now(UTC)
    flow = db.scalar(
        select(OIDCAuthFlow)
        .where(OIDCAuthFlow.state_hash == hash_opaque(f"{state}.{binding}"))
        .with_for_update()
    )
    if not flow_is_usable(flow, now):
        raise HTTPException(status_code=401, detail="Invalid or expired authentication state")
    flow.consumed_at = now
    # Persist consumption before any remote exchange so failed callbacks cannot replay state.
    db.commit()
    try:
        claims = validate_id_token(
            _exchange_code(code, flow.code_verifier),
            issuer=settings.oidc_issuer,
            audience=settings.oidc_client_id,
            nonce=flow.nonce,
            jwks=load_jwks(settings),
        )
        role = role_from_claims(claims, settings)
    except OIDCValidationError as exc:
        raise HTTPException(status_code=401, detail="OIDC authentication failed") from exc

    tenant = db.scalar(select(Tenant).where(Tenant.key == "default", Tenant.status == "active"))
    if tenant is None:
        raise HTTPException(status_code=401, detail="Tenant is unavailable")
    identity = db.scalar(
        select(Identity).where(
            Identity.issuer == settings.oidc_issuer,
            Identity.subject == claims["sub"],
        )
    )
    if identity is None:
        if not settings.oidc_jit_provisioning:
            raise HTTPException(status_code=403, detail="Membership required")
        identity = Identity(
            issuer=settings.oidc_issuer,
            subject=claims["sub"],
            display_name=str(claims.get("name") or claims["sub"])[:200],
            email=str(claims["email"])[:320] if claims.get("email") else None,
        )
        db.add(identity)
        db.flush()
    membership = db.scalar(
        select(TenantMembership).where(
            TenantMembership.tenant_id == tenant.id,
            TenantMembership.identity_id == identity.id,
        )
    )
    if membership is None:
        if not settings.oidc_jit_provisioning:
            raise HTTPException(status_code=403, detail="Membership required")
        membership = TenantMembership(tenant_id=tenant.id, identity_id=identity.id, role=role)
        db.add(membership)
    else:
        membership.role = role
    workspace = db.scalar(
        select(Workspace).where(
            Workspace.tenant_id == tenant.id,
            Workspace.key == settings.default_workspace_key,
            Workspace.status == "active",
        )
    )
    if workspace is not None:
        workspace_membership = _workspace_membership(db, workspace.id, identity)
        workspace_role = "workspace-admin" if role == "platform-admin" else role
        if workspace_membership is None and settings.oidc_jit_provisioning:
            db.add(
                WorkspaceMembership(
                    workspace_id=workspace.id,
                    identity_id=identity.id,
                    subject=identity.subject,
                    role=workspace_role,
                )
            )
        else:
            workspace_membership.role = workspace_role
    opaque = create_session(
        db,
        identity=identity,
        tenant_id=tenant.id,
        role=role,
        minutes=settings.auth_session_minutes,
    )
    record_audit(db, entity_type="session", entity_id=identity.id, action="login", actor=identity.subject, payload={"event": "login"})
    response = RedirectResponse(flow.return_to, status_code=303)
    expire_browser_cookies(response)
    _set_cookie(
        response,
        settings,
        SESSION_COOKIE,
        opaque,
        httponly=True,
        max_age=settings.auth_session_minutes * 60,
    )
    _set_cookie(response, settings, CSRF_COOKIE, secrets.token_urlsafe(32), httponly=False, max_age=settings.auth_session_minutes * 60)
    _delete_flow_cookie(response)
    return response


@router.get("/session")
def current_session(request: Request, db: DbSession):
    identity_id = getattr(request.state, "identity_id", None)
    tenant_id = getattr(request.state, "tenant_id", None)
    if identity_id is None or tenant_id is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    identity = db.get(Identity, identity_id)
    tenant = db.get(Tenant, tenant_id)
    if identity is None or identity.status != "active" or tenant is None or tenant.status != "active":
        raise HTTPException(status_code=401, detail="Authentication required")
    workspace = db.scalar(
        select(Workspace)
        .join(WorkspaceMembership, WorkspaceMembership.workspace_id == Workspace.id)
        .where(
            WorkspaceMembership.identity_id == identity.id,
            Workspace.tenant_id == tenant.id,
            Workspace.status == "active",
        )
        .order_by(Workspace.key)
    )
    if workspace is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    settings = get_settings()
    role = str(getattr(request.state, "role", ""))
    email = (identity.email or identity.subject or "").strip()
    body = {
        "display_name": (identity.display_name or email or "Signed-in user").strip(),
        "account": email,
        "role": role,
        "workspace_name": workspace.name,
        "workspace_key": workspace.key,
        "tenant_name": tenant.name,
        "data_context": "Synthetic reference",
        "logout_available": settings.normalized_auth_mode in {"local", "oidc"},
    }
    return JSONResponse(body, headers={"cache-control": "no-store"})


@router.post("/logout", status_code=204)
def logout(request: Request, db: DbSession):
    seen: set[str] = set()
    for opaque in presented_session_tokens(request.headers.get("cookie") or ""):
        if opaque in seen:
            continue
        seen.add(opaque)
        record = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_opaque(opaque)))
        if record is not None and record.revoked_at is None:
            record.revoked_at = datetime.now(UTC)
            record_audit(
                db,
                entity_type="session",
                entity_id=record.identity_id,
                action="logout",
                actor="authenticated-session",
                payload={"event": "logout"},
            )
    response = Response(status_code=204, headers={"cache-control": "no-store"})
    expire_browser_cookies(response)
    return response


def _set_cookie(response: RedirectResponse, settings, base: str, value: str, *, httponly: bool, max_age: int) -> None:
    response.set_cookie(
        browser_cookie_name(base, secure=settings.is_production),
        value,
        max_age=max_age,
        httponly=httponly,
        secure=settings.is_production,
        samesite="lax",
        path="/",
    )


def _delete_flow_cookie(response: RedirectResponse) -> None:
    for secure in (True, False):
        response.delete_cookie(browser_cookie_name(FLOW_COOKIE, secure=secure), path="/")


def _workspace_membership(db, workspace_id, identity: Identity) -> WorkspaceMembership | None:
    matched = db.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace_id,
            WorkspaceMembership.identity_id == identity.id,
        )
    )
    if matched is not None:
        return matched
    legacy = db.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace_id,
            WorkspaceMembership.subject == identity.subject,
        )
    )
    if legacy is None:
        return None
    if legacy.identity_id not in (None, identity.id):
        linked = db.get(Identity, legacy.identity_id)
        if linked is None or linked.issuer != "urn:threatsight:legacy" or linked.subject != identity.subject:
            raise HTTPException(status_code=409, detail="Workspace membership conflict")
    legacy.identity_id = identity.id
    return legacy
