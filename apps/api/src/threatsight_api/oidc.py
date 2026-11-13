from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.config import Settings, get_settings
from threatsight_api.persistence.models import AuthSession, Identity, LocalCredential, Tenant, TenantMembership
from threatsight_api.url_safety import open_unredirected

CANONICAL_ROLES = frozenset({"operator", "auditor", "viewer", "workspace-admin", "platform-admin"})
ROLE_ALIASES = {"reviewer": "operator", "admin": "workspace-admin"}
SESSION_COOKIE = "threatsight_session"
FLOW_COOKIE = "threatsight_oidc"
CSRF_COOKIE = "threatsight_csrf"
ID_TOKEN_CLOCK_SKEW_SECONDS = 60
ID_TOKEN_MAX_AGE_SECONDS = 600


def browser_cookie_name(base: str, *, secure: bool) -> str:
    return f"__Host-{base}" if secure else base


# Python's cookie formatter treats an integer expiry of 0 as "now", not the epoch.
# A deletion must carry an unambiguous past date plus Max-Age=0.
COOKIE_EXPIRED = datetime(1970, 1, 1, tzinfo=UTC)


def presented_authentication_token(cookies, *, production: bool) -> str:
    """Return the session token production will honor.

    Production accepts only the host-bound Secure cookie. A legacy non-Secure
    cookie is ignored even when it is also present.
    """
    host = str(cookies.get(f"__Host-{SESSION_COOKIE}") or "").strip()
    if production:
        return host
    return host or str(cookies.get(SESSION_COOKIE) or "").strip()


def presented_session_tokens(cookie_header: str) -> list[str]:
    names = {SESSION_COOKIE, f"__Host-{SESSION_COOKIE}"}
    tokens: list[str] = []
    for part in cookie_header.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name in names and value.strip():
            tokens.append(value.strip())
    return tokens


def expire_browser_cookies(response: Any) -> None:
    """Expire the canonical cookies and the legacy variants this deployment has issued."""
    variants = (
        (SESSION_COOKIE, False, True),
        (SESSION_COOKIE, True, True),
        (f"__Host-{SESSION_COOKIE}", True, True),
        (CSRF_COOKIE, False, False),
        (CSRF_COOKIE, True, False),
        (f"__Host-{CSRF_COOKIE}", True, False),
        (FLOW_COOKIE, False, True),
        (FLOW_COOKIE, True, True),
        (f"__Host-{FLOW_COOKIE}", True, True),
    )
    for name, secure, httponly in variants:
        response.set_cookie(
            name,
            "",
            max_age=0,
            expires=COOKIE_EXPIRED,
            path="/",
            secure=secure,
            httponly=httponly,
            samesite="lax",
        )


class OIDCValidationError(ValueError):
    pass


def canonical_role(role: str) -> str:
    normalized = ROLE_ALIASES.get(role.strip().lower(), role.strip().lower())
    if normalized not in CANONICAL_ROLES:
        raise OIDCValidationError("unsupported role")
    return normalized


def _b64decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise OIDCValidationError("invalid base64 encoding") from exc


def _json_segment(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64decode(value))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OIDCValidationError("invalid JWT JSON") from exc
    if not isinstance(decoded, dict):
        raise OIDCValidationError("invalid JWT object")
    return decoded


def validate_id_token(
    token: str,
    *,
    issuer: str,
    audience: str,
    nonce: str,
    jwks: dict[str, Any],
    now: int | None = None,
) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise OIDCValidationError("invalid JWT structure")
    header, claims = _json_segment(parts[0]), _json_segment(parts[1])
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise OIDCValidationError("only keyed RS256 tokens are accepted")
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise OIDCValidationError("invalid JWKS")
    key = next(
        (item for item in keys if isinstance(item, dict) and item.get("kid") == header["kid"]),
        None,
    )
    if key is None or key.get("kty") != "RSA" or key.get("use", "sig") != "sig":
        raise OIDCValidationError("signing key not found")
    try:
        public_key = rsa.RSAPublicNumbers(
            int.from_bytes(_b64decode(str(key["e"])), "big"),
            int.from_bytes(_b64decode(str(key["n"])), "big"),
        ).public_key()
        public_key.verify(
            _b64decode(parts[2]),
            f"{parts[0]}.{parts[1]}".encode("ascii"),
            padding.PKCS1v15(),
            SHA256(),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise OIDCValidationError("invalid signing key") from exc
    except Exception as exc:
        raise OIDCValidationError("invalid token signature") from exc

    current = int(time.time()) if now is None else now
    if claims.get("iss") != issuer:
        raise OIDCValidationError("issuer mismatch")
    token_audience = claims.get("aud")
    audiences = [token_audience] if isinstance(token_audience, str) else token_audience
    if not isinstance(audiences, list) or audience not in audiences:
        raise OIDCValidationError("audience mismatch")
    if len(audiences) > 1 and claims.get("azp") != audience:
        raise OIDCValidationError("authorized party mismatch")
    if not isinstance(claims.get("exp"), int) or claims["exp"] <= current:
        raise OIDCValidationError("token expired")
    if not isinstance(claims.get("iat"), int):
        raise OIDCValidationError("issued-at missing")
    if claims["iat"] > current + ID_TOKEN_CLOCK_SKEW_SECONDS:
        raise OIDCValidationError("issued-at is in the future")
    if current - claims["iat"] > ID_TOKEN_MAX_AGE_SECONDS:
        raise OIDCValidationError("issued-at is too old")
    if isinstance(claims.get("nbf"), int) and claims["nbf"] > current + ID_TOKEN_CLOCK_SKEW_SECONDS:
        raise OIDCValidationError("token not yet valid")
    if claims.get("nonce") != nonce:
        raise OIDCValidationError("nonce mismatch")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OIDCValidationError("subject missing")
    return claims


def _group_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def role_from_claims(claims: dict[str, Any], settings: Settings) -> str:
    groups = claims.get("groups", [])
    if not isinstance(groups, list) or not all(isinstance(item, str) for item in groups):
        raise OIDCValidationError("groups claim is invalid")
    memberships = set(groups)
    mappings = (
        ("platform-admin", settings.oidc_platform_admin_groups),
        ("workspace-admin", settings.oidc_workspace_admin_groups),
        ("operator", settings.oidc_operator_groups),
        ("auditor", settings.oidc_auditor_groups),
    )
    for role, configured in mappings:
        if memberships & _group_set(configured):
            return role
    raise OIDCValidationError("no authorized role mapping")


def hash_opaque(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_opaque_token() -> str:
    return secrets.token_urlsafe(48)


def pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def load_jwks(settings: Settings) -> dict[str, Any]:
    try:
        with open_unredirected(settings.oidc_jwks_uri, production=settings.is_production) as response:
            if response.status != 200:
                raise OIDCValidationError("JWKS request failed")
            payload = response.read(1_048_577)
    except OIDCValidationError:
        raise
    except Exception as exc:
        raise OIDCValidationError("JWKS request failed") from exc
    if len(payload) > 1_048_576:
        raise OIDCValidationError("JWKS response too large")
    try:
        result = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise OIDCValidationError("invalid JWKS JSON") from exc
    if not isinstance(result, dict):
        raise OIDCValidationError("invalid JWKS object")
    return result


@dataclass(frozen=True)
class SessionPrincipal:
    identity_id: str
    tenant_id: str
    subject: str
    role: str


def resolve_session(session: Session, opaque_token: str, now: datetime | None = None) -> SessionPrincipal | None:
    current = now or datetime.now(UTC)
    record = session.scalar(
        select(AuthSession).where(AuthSession.token_hash == hash_opaque(opaque_token))
    )
    if record is None or record.revoked_at is not None or record.expires_at <= current:
        return None
    idle_minutes = get_settings().auth_idle_minutes
    activity = record.last_seen_at or getattr(record, "created_at", None)
    if activity is not None and activity <= current - timedelta(minutes=idle_minutes):
        record.revoked_at = current
        return None
    identity = session.get(Identity, record.identity_id)
    membership = session.scalar(
        select(TenantMembership).where(
            TenantMembership.tenant_id == record.tenant_id,
            TenantMembership.identity_id == record.identity_id,
        )
    )
    tenant = session.get(Tenant, record.tenant_id)
    if (
        identity is None
        or identity.status != "active"
        or tenant is None
        or tenant.status != "active"
        or membership is None
    ):
        return None
    if getattr(identity, "issuer", None) == "urn:threatsight:local":
        credential = session.scalar(select(LocalCredential).where(LocalCredential.identity_id == identity.id))
        if credential is None or not credential.enabled:
            record.revoked_at = current
            return None
    try:
        session_role = canonical_role(record.role)
        effective = canonical_role(membership.role)
    except OIDCValidationError:
        record.revoked_at = current
        return None
    if session_role != effective:
        record.revoked_at = current
        return None
    record.last_seen_at = current
    return SessionPrincipal(
        identity_id=str(identity.id),
        tenant_id=str(record.tenant_id),
        subject=identity.subject,
        role=effective,
    )


def create_session(
    session: Session,
    *,
    identity: Identity,
    tenant_id: Any,
    role: str,
    minutes: int,
) -> str:
    opaque = new_opaque_token()
    session.add(
        AuthSession(
            token_hash=hash_opaque(opaque),
            identity_id=identity.id,
            tenant_id=tenant_id,
            role=canonical_role(role),
            expires_at=datetime.now(UTC) + timedelta(minutes=minutes),
        )
    )
    return opaque
