"""Read-only API tokens for exports, Power BI and other tools.

A token looks like ``tsk_<prefix>_<secret>``. Only its SHA-256 is stored. It works while it is not
revoked and its identity and tenant are still active, and only for reading: GET and HEAD, never the
sign-in, owner or alert-destination routes. Checks are cached for a minute, so revoking takes effect
within one.
"""
from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.integration_models import ApiToken
from threatsight_api.persistence.models import Identity, Tenant, TenantMembership

PREFIX = "tsk_"
CACHE_SECONDS = 60
_cache: dict[str, tuple[float, dict[str, Any] | None]] = {}


def new_token() -> tuple[str, str, str]:
    """Returns (token, prefix, sha256)."""
    prefix = secrets.token_hex(4)
    token = f"{PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
    return token, prefix, digest(token)


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def looks_like_token(value: str) -> bool:
    return value.startswith(PREFIX) and 20 <= len(value) <= 200


def lookup(db: Session, token: str) -> dict[str, Any] | None:
    """Who a token belongs to, or None when it is unknown, revoked, or its identity lost access."""
    key = digest(token)
    now = time.monotonic()
    cached = _cache.get(key)
    if cached and now - cached[0] < CACHE_SECONDS:
        return cached[1]
    row = db.scalar(select(ApiToken).where(ApiToken.token_hash == key))
    info = None
    if row is not None and row.revoked_at is None:
        identity = db.get(Identity, row.identity_id)
        tenant = db.get(Tenant, row.tenant_id)
        member = db.scalar(
            select(TenantMembership).where(
                TenantMembership.tenant_id == row.tenant_id, TenantMembership.identity_id == row.identity_id
            )
        )
        if identity is not None and identity.status == "active" and tenant is not None and tenant.status == "active" and member is not None:
            info = {
                "identity_id": identity.id,
                "tenant_id": row.tenant_id,
                "actor": identity.subject,
                "token_id": str(row.id),
                "token_name": row.name,
            }
            row.last_used_at = datetime.now(UTC)
    _cache[key] = (now, info)
    return info


def forget(token_id: uuid.UUID | str) -> None:
    """Drop cached checks for a token right away (called when it is revoked)."""
    for key, (_, info) in list(_cache.items()):
        if info and info.get("token_id") == str(token_id):
            _cache.pop(key, None)
