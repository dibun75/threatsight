"""Local account operations. Raw tokens and passwords stay out of logs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatsight_api.local_auth import LOCAL_ISSUER
from threatsight_api.local_auth.passwords import PasswordRejected, hash_password, needs_rehash, validate_password, verify_password
from threatsight_api.config import get_settings
from threatsight_api.oidc import OIDCValidationError, canonical_role, create_session, hash_opaque, new_opaque_token
from threatsight_api.persistence.models import (
    AuthSession,
    Identity,
    LocalAuthThrottle,
    LocalAuthToken,
    LocalCredential,
    Tenant,
    TenantMembership,
    Workspace,
    WorkspaceMembership,
)
from threatsight_api.services.audit import record_audit


class LocalAuthError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail


def normalize_email(value: str) -> str:
    email = value.strip().casefold()
    if not email or len(email) > 320 or "@" not in email or any(char.isspace() for char in email):
        raise LocalAuthError(400, "Sign-in failed.")
    return email


def _throttle(db: Session, key: str, now: datetime) -> LocalAuthThrottle:
    row = db.get(LocalAuthThrottle, hash_opaque(key))
    if row is None:
        row = LocalAuthThrottle(subject_hash=hash_opaque(key), failures=0)
        db.add(row)
        db.flush()
    if row.locked_until is not None and row.locked_until > now:
        raise LocalAuthError(429, "Sign-in failed.")
    return row


def _fail(row: LocalAuthThrottle, now: datetime) -> None:
    row.failures += 1
    row.updated_at = now
    if row.failures >= 8:
        row.locked_until = now + timedelta(minutes=15)
    elif row.failures >= 5:
        row.locked_until = now + timedelta(seconds=30)


def _reset(row: LocalAuthThrottle, now: datetime) -> None:
    row.failures = 0
    row.locked_until = None
    row.updated_at = now


def authenticate(db: Session, *, email: str, password: str, source: str) -> tuple[Identity, str]:
    now = datetime.now(UTC)
    account_key = f"account:{email.strip().casefold()}"
    source_key = f"source:{source}"
    account_row = _throttle(db, account_key, now)
    source_row = _throttle(db, source_key, now)
    credential = db.scalar(select(LocalCredential).where(LocalCredential.email == email.strip().casefold()))
    identity = db.get(Identity, credential.identity_id) if credential is not None else None
    membership = None
    workspace_membership = None
    if identity is not None:
        membership = db.scalar(
            select(TenantMembership)
            .join(Tenant, Tenant.id == TenantMembership.tenant_id)
            .where(TenantMembership.identity_id == identity.id, Tenant.status == "active")
            .order_by(Tenant.key)
        )
        workspace_membership = db.scalar(select(WorkspaceMembership).where(WorkspaceMembership.identity_id == identity.id))
    verified = verify_password(password, credential.password_hash if credential is not None else None)
    accepted = bool(
        verified
        and credential is not None
        and credential.enabled
        and identity is not None
        and identity.status == "active"
        and membership is not None
        and workspace_membership is not None
    )
    if not accepted:
        _fail(account_row, now)
        _fail(source_row, now)
        record_audit(
            db,
            entity_type="local_auth",
            entity_id=uuid.UUID(int=0),
            action="login_failure",
            actor="local-auth",
            payload={"event": "login_failure"},
        )
        raise LocalAuthError(401, "Sign-in failed.")
    if needs_rehash(credential.password_hash):
        credential.password_hash = hash_password(password)
    credential.last_login_at = now
    credential.updated_at = now
    _reset(account_row, now)
    role = canonical_role(membership.role)
    revoke_sessions(db, identity.id)
    opaque = create_session(
        db,
        identity=identity,
        tenant_id=membership.tenant_id,
        role=role,
        minutes=get_settings().auth_session_minutes,
    )
    record_audit(db, entity_type="session", entity_id=identity.id, action="login", actor=identity.subject, payload={"event": "login"})
    return identity, opaque


def create_account(
    db: Session,
    *,
    email: str,
    password: str,
    role: str,
    tenant: Tenant,
    workspace: Workspace,
) -> Identity:
    normalized = normalize_email(email)
    try:
        canonical = canonical_role(role)
    except OIDCValidationError as exc:
        raise LocalAuthError(400, "Account not found.") from exc
    if db.scalar(select(LocalCredential).where(LocalCredential.email == normalized)) is not None:
        raise LocalAuthError(409, "Account already exists.")
    identity = db.scalar(
        select(Identity).where(Identity.issuer == LOCAL_ISSUER, Identity.subject == normalized)
    )
    if identity is None:
        identity = Identity(issuer=LOCAL_ISSUER, subject=normalized, display_name=normalized, email=normalized, status="active")
        db.add(identity)
        db.flush()
    db.add(
        LocalCredential(
            identity_id=identity.id,
            email=normalized,
            password_hash=hash_password(password),
            enabled=True,
        )
    )
    if db.scalar(select(TenantMembership).where(TenantMembership.identity_id == identity.id, TenantMembership.tenant_id == tenant.id)) is None:
        db.add(TenantMembership(tenant_id=tenant.id, identity_id=identity.id, role=canonical))
    if db.scalar(select(WorkspaceMembership).where(WorkspaceMembership.workspace_id == workspace.id, WorkspaceMembership.subject == normalized)) is None:
        db.add(WorkspaceMembership(workspace_id=workspace.id, identity_id=identity.id, subject=normalized, role=canonical))
    record_audit(db, entity_type="local_auth", entity_id=identity.id, action="create", actor="local-auth", payload={"event": "account_created"})
    return identity


def issue_token(db: Session, *, email: str, role: str, tenant_id, workspace_id, purpose: str, issuer_id=None) -> str:
    raw = new_opaque_token()
    try:
        role_name = canonical_role(role)
    except OIDCValidationError as exc:
        raise LocalAuthError(400, "Account not found.") from exc
    db.add(
        LocalAuthToken(
            token_hash=hash_opaque(raw),
            purpose=purpose,
            email=normalize_email(email),
            role=role_name,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            issuer_id=issuer_id,
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        )
    )
    record_audit(db, entity_type="local_auth", entity_id=tenant_id, action="create", actor="local-auth", payload={"event": f"{purpose}_issued"})
    return raw


def consume_token(db: Session, *, raw: str, password: str, purpose: str) -> None:
    try:
        validate_password(password)
    except PasswordRejected as exc:
        raise LocalAuthError(400, "Choose a different password.") from exc
    now = datetime.now(UTC)
    row = db.scalar(select(LocalAuthToken).where(LocalAuthToken.token_hash == hash_opaque(raw)).with_for_update())
    if row is None or row.purpose != purpose or row.consumed_at is not None or row.revoked_at is not None or row.expires_at <= now:
        raise LocalAuthError(400, "This link is not valid.")
    tenant = db.get(Tenant, row.tenant_id)
    workspace = db.get(Workspace, row.workspace_id)
    if tenant is None or workspace is None:
        raise LocalAuthError(400, "This link is not valid.")
    existing = db.scalar(select(LocalCredential).where(LocalCredential.email == row.email))
    if existing is None:
        create_account(db, email=row.email, password=password, role=row.role, tenant=tenant, workspace=workspace)
    else:
        existing.password_hash = hash_password(password)
        existing.password_changed_at = now
        existing.enabled = True
        revoke_sessions(db, existing.identity_id)
    row.consumed_at = now
    record_audit(db, entity_type="local_auth", entity_id=row.id, action="update", actor="local-auth", payload={"event": f"{purpose}_consumed"})


def revoke_sessions(db: Session, identity_id) -> int:
    now = datetime.now(UTC)
    rows = db.scalars(select(AuthSession).where(AuthSession.identity_id == identity_id, AuthSession.revoked_at.is_(None))).all()
    for row in rows:
        row.revoked_at = now
    return len(rows)


def account_in_tenant(db: Session, *, email: str, tenant_id):
    try:
        normalized = normalize_email(email)
    except LocalAuthError:
        return None
    credential = db.scalar(select(LocalCredential).where(LocalCredential.email == normalized))
    if credential is None:
        return None
    membership = db.scalar(
        select(TenantMembership).where(
            TenantMembership.identity_id == credential.identity_id,
            TenantMembership.tenant_id == tenant_id,
        )
    )
    if membership is None:
        return None
    return credential, membership


def set_enabled(db: Session, *, actor_id, tenant_id, email: str, enabled: bool) -> None:
    found = account_in_tenant(db, email=email, tenant_id=tenant_id)
    if found is None:
        raise LocalAuthError(404, "Account not found.")
    credential, membership = found
    if credential.identity_id == actor_id:
        raise LocalAuthError(403, "Role is read-only")
    if not enabled and membership.role == "platform-admin" and enabled_owner_count(db, tenant_id) <= 1:
        raise LocalAuthError(409, "The last recovery administrator cannot be disabled.")
    credential.enabled = enabled
    credential.updated_at = datetime.now(UTC)
    if not enabled:
        revoke_sessions(db, credential.identity_id)
    record_audit(
        db,
        entity_type="local_auth",
        entity_id=credential.id,
        action="update",
        actor="local-auth",
        payload={"event": "account_enabled" if enabled else "account_disabled"},
    )


def assign_role(db: Session, *, actor_id, tenant_id, email: str, role: str) -> None:
    found = account_in_tenant(db, email=email, tenant_id=tenant_id)
    if found is None:
        raise LocalAuthError(404, "Account not found.")
    credential, membership = found
    if credential.identity_id == actor_id:
        raise LocalAuthError(403, "Role is read-only")
    try:
        canonical = canonical_role(role)
    except OIDCValidationError as exc:
        raise LocalAuthError(400, "Account not found.") from exc
    if membership.role == "platform-admin" and canonical != "platform-admin" and enabled_owner_count(db, tenant_id) <= 1:
        raise LocalAuthError(409, "The last recovery administrator cannot be disabled.")
    membership.role = canonical
    workspace_rows = db.scalars(
        select(WorkspaceMembership).where(WorkspaceMembership.identity_id == credential.identity_id)
    ).all()
    for row in workspace_rows:
        row.role = canonical
    revoke_sessions(db, credential.identity_id)
    record_audit(db, entity_type="local_auth", entity_id=credential.id, action="update", actor="local-auth", payload={"event": "role_changed"})


def revoke_token(db: Session, *, token_id, tenant_id) -> None:
    row = db.get(LocalAuthToken, token_id)
    if row is None or row.tenant_id != tenant_id:
        raise LocalAuthError(404, "Account not found.")
    row.revoked_at = datetime.now(UTC)
    record_audit(db, entity_type="local_auth", entity_id=row.id, action="update", actor="local-auth", payload={"event": "token_revoked"})


def enabled_owner_count(db: Session, tenant_id) -> int:
    return db.scalar(
        select(func.count())
        .select_from(TenantMembership)
        .join(LocalCredential, LocalCredential.identity_id == TenantMembership.identity_id)
        .where(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.role == "platform-admin",
            LocalCredential.enabled.is_(True),
        )
    ) or 0
