from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from threatsight_api.api.auth import flow_is_usable
from threatsight_api.api.deps import tenant_matches
from threatsight_api.authz import AuthzMiddleware
from threatsight_api.config import Settings, get_settings
from threatsight_api.url_safety import endpoint_problem
from threatsight_api.oidc import (
    OIDCValidationError,
    SessionPrincipal,
    canonical_role,
    hash_opaque,
    resolve_session,
    role_from_claims,
    validate_id_token,
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class LocalTestIssuer:
    def __init__(self) -> None:
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = self.private.public_key().public_numbers()
        self.jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "local-test-key",
                    "use": "sig",
                    "alg": "RS256",
                    "n": _b64(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
                    "e": _b64(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")),
                }
            ]
        }

    def token(self, **overrides) -> str:
        now = int(time.time())
        claims = {
            "iss": "https://login.microsoftonline.com/test-tenant/v2.0",
            "aud": "threatsight-test",
            "sub": "entra-subject",
            "nonce": "expected-nonce",
            "iat": now,
            "exp": now + 300,
            "groups": ["operators"],
        }
        claims.update(overrides)
        header = {"alg": "RS256", "kid": "local-test-key", "typ": "JWT"}
        signing_input = (
            _b64(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64(json.dumps(claims, separators=(",", ":")).encode())
        )
        signature = self.private.sign(signing_input.encode(), padding.PKCS1v15(), SHA256())
        return signing_input + "." + _b64(signature)


def _validate(issuer: LocalTestIssuer, token: str):
    return validate_id_token(
        token,
        issuer="https://login.microsoftonline.com/test-tenant/v2.0",
        audience="threatsight-test",
        nonce="expected-nonce",
        jwks=issuer.jwks,
    )


def test_entra_compatible_rs256_validation_and_fail_closed_claims() -> None:
    issuer = LocalTestIssuer()
    assert _validate(issuer, issuer.token())["sub"] == "entra-subject"
    for token in (
        issuer.token(iss="https://attacker.invalid"),
        issuer.token(aud="other-client"),
        issuer.token(exp=int(time.time()) - 1),
        issuer.token(nonce="replayed-nonce"),
        issuer.token(iat=None),
        issuer.token(iat=int(time.time()) + 120),
        issuer.token(iat=int(time.time()) - 601),
    ):
        with pytest.raises(OIDCValidationError):
            _validate(issuer, token)
    other = LocalTestIssuer()
    with pytest.raises(OIDCValidationError, match="signature"):
        _validate(issuer, other.token())


def test_state_replay_and_expiry_fail_closed() -> None:
    now = datetime.now(UTC)
    flow = SimpleNamespace(consumed_at=None, expires_at=now + timedelta(minutes=1))
    assert flow_is_usable(flow, now)
    flow.consumed_at = now
    assert not flow_is_usable(flow, now)
    flow.consumed_at = None
    flow.expires_at = now
    assert not flow_is_usable(flow, now)


def test_role_mapping_compatibility_without_platform_admin_escalation() -> None:
    settings = Settings(
        oidc_operator_groups="operators",
        oidc_auditor_groups="auditors",
        oidc_workspace_admin_groups="workspace-admins",
        oidc_platform_admin_groups="break-glass-platform-admins",
    )
    assert canonical_role("reviewer") == "operator"
    assert canonical_role("admin") == "workspace-admin"
    assert role_from_claims({"groups": ["operators"]}, settings) == "operator"
    assert role_from_claims({"groups": ["workspace-admins"]}, settings) == "workspace-admin"
    with pytest.raises(OIDCValidationError):
        role_from_claims({"groups": ["admin"]}, settings)
    assert (
        role_from_claims({"groups": ["break-glass-platform-admins"]}, settings)
        == "platform-admin"
    )


def test_cross_tenant_scope_rejected() -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    assert tenant_matches(tenant_a, tenant_a)
    assert not tenant_matches(tenant_a, tenant_b)


class FakeSession:
    def __init__(self, record, identity, membership, tenant=None):
        self.record, self.identity, self.membership = record, identity, membership
        self.tenant = tenant or SimpleNamespace(status="active")

    def scalar(self, _statement):
        if self.record is not None:
            value, self.record = self.record, None
            return value
        return self.membership

    def get(self, model, _identity_id):
        if getattr(model, "__name__", "") == "Tenant":
            return self.tenant
        return self.identity


def test_opaque_session_expiry_revocation_and_hash_only_lookup() -> None:
    now = datetime.now(UTC)
    identity_id, tenant_id = uuid.uuid4(), uuid.uuid4()

    def record(**overrides):
        values = dict(
            token_hash=hash_opaque("opaque"),
            identity_id=identity_id,
            tenant_id=tenant_id,
            role="operator",
            expires_at=now + timedelta(minutes=5),
            revoked_at=None,
            last_seen_at=None,
        )
        values.update(overrides)
        return SimpleNamespace(**values)

    identity = SimpleNamespace(id=identity_id, subject="entra-subject", status="active")
    membership = SimpleNamespace(role="operator")
    assert resolve_session(FakeSession(record(), identity, membership), "opaque", now) is not None
    assert resolve_session(
        FakeSession(record(expires_at=now), identity, membership), "opaque", now
    ) is None
    assert resolve_session(
        FakeSession(record(revoked_at=now), identity, membership), "opaque", now
    ) is None
    stale = record(role="platform-admin")
    assert resolve_session(FakeSession(stale, identity, SimpleNamespace(role="operator")), "opaque", now) is None
    assert stale.revoked_at == now
    disabled = SimpleNamespace(id=identity_id, subject="entra-subject", status="disabled")
    assert resolve_session(FakeSession(record(), disabled, membership), "opaque", now) is None
    assert (
        resolve_session(
            FakeSession(record(), identity, membership, tenant=SimpleNamespace(status="disabled")),
            "opaque",
            now,
        )
        is None
    )


def test_oidc_session_ignores_spoofed_identity_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    class ContextSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def commit(self):
            return None

    monkeypatch.setenv("THREATSIGHT_AUTH_MODE", "oidc")
    monkeypatch.setattr("threatsight_api.authz.SessionLocal", ContextSession)
    monkeypatch.setattr(
        "threatsight_api.authz.resolve_session",
        lambda _db, _token: SessionPrincipal("identity", "tenant", "trusted-subject", "auditor"),
    )
    get_settings.cache_clear()
    app = FastAPI()
    app.add_middleware(AuthzMiddleware)

    @app.get("/api/whoami")
    def whoami(request: Request):
        return {"actor": request.state.actor, "role": request.state.role}

    try:
        with TestClient(app) as client:
            response = client.get(
                "/api/whoami",
                cookies={"threatsight_session": "opaque"},
                headers={"X-Actor": "attacker", "X-Role": "platform-admin"},
            )
        assert response.json() == {"actor": "trusted-subject", "role": "auditor"}
    finally:
        get_settings.cache_clear()


def test_production_requires_complete_oidc_configuration() -> None:
    with pytest.raises(ValueError, match="local or oidc"):
        Settings(env="production").validate_runtime_security()
    safe = Settings(
        env="production",
        auth_mode="oidc",
        oidc_issuer="https://login.microsoftonline.com/tenant/v2.0",
        oidc_audience="api://threatsight",
        oidc_client_id="client",
        oidc_authorization_endpoint="https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
        oidc_token_endpoint="https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        oidc_jwks_uri="https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
        oidc_redirect_uri="https://threatsight.example/api/v1/auth/callback",
        database_url="postgresql+psycopg://threatsight:strong-secret@postgres:5432/threatsight",
        cors_origins="https://threatsight.example",
        openapi_enabled=False,
    )
    safe.validate_runtime_security()
    unsafe = Settings(
        env="production",
        auth_mode="oidc",
        oidc_issuer="https://login.microsoftonline.com/tenant/v2.0",
        oidc_audience="api://threatsight",
        oidc_client_id="client",
        oidc_authorization_endpoint="http://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
        oidc_token_endpoint="https://169.254.169.254/token",
        oidc_jwks_uri="https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
        oidc_redirect_uri="https://threatsight.example/api/v1/auth/callback",
        database_url="postgresql+psycopg://threatsight:strong-secret@postgres:5432/threatsight",
        cors_origins="https://other.example",
    )
    with pytest.raises(ValueError, match="HTTPS|public address|CORS"):
        unsafe.validate_runtime_security()
    assert endpoint_problem("https://user:secret@login.example/token") == "must not include credentials or a fragment"


def test_oidc_cookie_writes_require_origin_and_csrf(monkeypatch: pytest.MonkeyPatch) -> None:
    class ContextSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def commit(self):
            return None

    monkeypatch.setenv("THREATSIGHT_AUTH_MODE", "oidc")
    monkeypatch.setenv("THREATSIGHT_CORS_ORIGINS", "https://threatsight.example")
    monkeypatch.setattr("threatsight_api.authz.SessionLocal", ContextSession)
    monkeypatch.setattr(
        "threatsight_api.authz.resolve_session",
        lambda _db, _token: SessionPrincipal("identity", "tenant", "trusted-subject", "operator"),
    )
    get_settings.cache_clear()
    app = FastAPI()
    app.add_middleware(AuthzMiddleware)

    @app.post("/api/write")
    def write():
        return {"ok": True}

    cookies = {"threatsight_session": "opaque", "threatsight_csrf": "csrf-value"}
    try:
        with TestClient(app) as client:
            blocked = client.post("/api/write", cookies=cookies)
            cross_site = client.post(
                "/api/write",
                cookies=cookies,
                headers={"Origin": "https://evil.example", "X-CSRF-Token": "csrf-value"},
            )
            allowed = client.post(
                "/api/write",
                cookies=cookies,
                headers={"Origin": "https://threatsight.example", "X-CSRF-Token": "csrf-value"},
            )
        assert blocked.status_code == 403
        assert cross_site.status_code == 403
        assert allowed.status_code == 200
    finally:
        get_settings.cache_clear()
