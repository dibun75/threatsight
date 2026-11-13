"""Full generic-OIDC fail-closed matrix for Phase 3G.

Browser automation against disposable Keycloak is orchestrated by
`deploy/scripts/oidc_disposable_acceptance.sh`. This module proves the
protocol invariants the browser flow depends on (including secure cookies,
replay, and recovery-admin mapping) without touching live credentials.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from threatsight_api.api.auth import flow_is_usable
from threatsight_api.config import Settings
from threatsight_api.oidc import (
    OIDCValidationError,
    browser_cookie_name,
    presented_authentication_token,
    role_from_claims,
    validate_id_token,
)

ISSUER = "https://127.0.0.1:18443/realms/threatsight"
AUD = "threatsight-api"


def _b64(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class _Issuer:
    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = self.private.public_key().public_numbers()
        self.jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "disp",
                    "use": "sig",
                    "alg": "RS256",
                    "n": _b64(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
                    "e": _b64(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")),
                }
            ]
        }

    def token(self, **overrides) -> str:
        import json

        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.hashes import SHA256

        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": AUD,
            "sub": "disp-user",
            "nonce": "n1",
            "iat": now,
            "exp": now + 300,
            "groups": ["operators"],
        }
        claims.update(overrides)
        header = {"alg": "RS256", "kid": "disp", "typ": "JWT"}
        signing_input = (
            _b64(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64(json.dumps(claims, separators=(",", ":")).encode())
        )
        signature = self.private.sign(signing_input.encode(), padding.PKCS1v15(), SHA256())
        return signing_input + "." + _b64(signature)


@pytest.mark.parametrize(
    "bad",
    [
        {"iss": "https://evil.example/realms/x"},
        {"aud": "wrong"},
        {"nonce": "replay"},
        {"exp": int(time.time()) - 30},
    ],
)
def test_oidc_browser_contract_rejects_bad_claims(bad: dict) -> None:
    issuer = _Issuer()
    base = {"iss": ISSUER, "aud": AUD, "nonce": "n1"}
    base.update(bad)
    with pytest.raises(OIDCValidationError):
        validate_id_token(
            issuer.token(**base),
            issuer=ISSUER,
            audience=AUD,
            nonce="n1",
            jwks=issuer.jwks,
        )


def test_oidc_browser_contract_accepts_valid_login_token() -> None:
    issuer = _Issuer()
    claims = validate_id_token(
        issuer.token(),
        issuer=ISSUER,
        audience=AUD,
        nonce="n1",
        jwks=issuer.jwks,
    )
    assert claims["sub"] == "disp-user"


def test_state_nonce_replay_and_logout_cookie_contract() -> None:
    now = datetime.now(UTC)
    assert not flow_is_usable(None, now)
    assert not flow_is_usable(
        SimpleNamespace(consumed_at=now, expires_at=now + timedelta(minutes=5)), now
    )
    assert browser_cookie_name("threatsight_session", secure=True) == "__Host-threatsight_session"
    assert presented_authentication_token({"threatsight_session": "legacy"}, production=True) == ""
    assert (
        presented_authentication_token({"__Host-threatsight_session": "ok"}, production=True) == "ok"
    )


def test_recovery_admin_group_mapping_and_unknown_disabled() -> None:
    settings = Settings(
        oidc_operator_groups="operators",
        oidc_auditor_groups="auditors",
        oidc_workspace_admin_groups="workspace-admins",
        oidc_platform_admin_groups="break-glass-platform-admins",
    )
    assert role_from_claims({"groups": ["break-glass-platform-admins"]}, settings) == "platform-admin"
    with pytest.raises(OIDCValidationError):
        role_from_claims({"groups": ["unknown"]}, settings)
