"""Enterprise OIDC fail-closed matrix (Phase 3F).

Uses an in-process RSA issuer. Disposable Keycloak validation is exercised by
deploy/validation scripts — this suite proves claim/session invariants without
live credentials.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from threatsight_api.api.auth import flow_is_usable
from threatsight_api.config import Settings
from threatsight_api.oidc import (
    OIDCValidationError,
    browser_cookie_name,
    presented_authentication_token,
    role_from_claims,
    validate_id_token,
)

ISSUER = "https://login.example/realms/threatsight"
AUD = "threatsight-api"


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
            "iss": ISSUER,
            "aud": AUD,
            "sub": "user-1",
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
        issuer=ISSUER,
        audience=AUD,
        nonce="expected-nonce",
        jwks=issuer.jwks,
    )


def test_login_token_accepts_valid_claims() -> None:
    issuer = LocalTestIssuer()
    token = issuer.token(iss=ISSUER, aud=AUD, nonce="expected-nonce")
    assert _validate(issuer, token)["sub"]


@pytest.mark.parametrize(
    "override",
    [
        {"iss": "https://attacker.invalid"},
        {"aud": "wrong-audience"},
        {"nonce": "wrong-nonce"},
        {"exp": int(time.time()) - 10},
    ],
)
def test_wrong_issuer_audience_nonce_expiry_fail_closed(override: dict) -> None:
    issuer = LocalTestIssuer()
    base = {"iss": ISSUER, "aud": AUD, "nonce": "expected-nonce"}
    base.update(override)
    token = issuer.token(**base)
    with pytest.raises(OIDCValidationError):
        _validate(issuer, token)


def test_missing_nonce_and_state_flow_fail_closed() -> None:
    issuer = LocalTestIssuer()
    token = issuer.token(iss=ISSUER, aud=AUD, nonce="expected-nonce")
    with pytest.raises(OIDCValidationError):
        validate_id_token(token, issuer=ISSUER, audience=AUD, nonce="", jwks=issuer.jwks)
    now = datetime.now(UTC)
    assert not flow_is_usable(None, now)
    consumed = SimpleNamespace(consumed_at=now, expires_at=now + timedelta(minutes=5))
    assert not flow_is_usable(consumed, now)


def test_replay_consumed_flow_rejected() -> None:
    now = datetime.now(UTC)
    flow = SimpleNamespace(consumed_at=now - timedelta(seconds=1), expires_at=now + timedelta(minutes=5))
    assert not flow_is_usable(flow, now)


def test_unknown_role_mapping_fail_closed() -> None:
    settings = Settings(
        oidc_operator_groups="operators",
        oidc_auditor_groups="auditors",
        oidc_workspace_admin_groups="workspace-admins",
        oidc_platform_admin_groups="break-glass-platform-admins",
    )
    assert role_from_claims({"groups": ["operators"]}, settings) == "operator"
    with pytest.raises(OIDCValidationError):
        role_from_claims({"groups": ["unknown-group"]}, settings)
    with pytest.raises(OIDCValidationError):
        role_from_claims({"groups": []}, settings)


def test_host_session_cookie_required_in_production() -> None:
    assert browser_cookie_name("threatsight_session", secure=True) == "__Host-threatsight_session"
    cookies = {"threatsight_session": "legacy", "__Host-threatsight_session": "hostbound"}
    assert presented_authentication_token(cookies, production=True) == "hostbound"
    assert presented_authentication_token({"threatsight_session": "legacy"}, production=True) == ""


def test_pilot_rejects_development_auth() -> None:
    with pytest.raises(ValueError):
        Settings(
            env="production",
            deployment_profile="pilot-compose",
            auth_mode="development",
            database_url="postgresql+psycopg://threatsight:strong-secret@db.example:5432/threatsight",
            cors_origins="https://threatsight.example",
            web_origins="https://threatsight.example",
            public_origin="https://threatsight.example",
            openapi_enabled=False,
            allow_synthetic_loaders=False,
        ).validate_runtime_security()
