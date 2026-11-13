from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from starlette.requests import Request
from threatsight_api.authz import role_may_write, token_matches
from threatsight_api.config import get_settings
from threatsight_api.main import app, create_app


def test_token_match_rejects_wrong_length() -> None:
    assert token_matches("abc", "abcd") is False
    assert token_matches("secret", "secret") is True


def test_auditor_is_read_only() -> None:
    assert role_may_write("auditor") is False
    assert role_may_write("operator") is True
    assert role_may_write("admin") is True


def test_lab_mode_allows_unauthenticated_meta() -> None:
    get_settings.cache_clear()
    with TestClient(app) as client:
        response = client.get("/api/v1/meta")
    assert response.status_code == 200
    assert response.json()["milestone"] == "M15"


def test_shared_token_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREATSIGHT_API_TOKEN", "s3cret-token-value")
    get_settings.cache_clear()
    try:
        with TestClient(app) as client:
            denied = client.get("/api/v1/meta")
            assert denied.status_code == 401
            health = client.get("/health")
            assert health.status_code == 200
            ok = client.get("/api/v1/meta", headers={"Authorization": "Bearer s3cret-token-value"})
            assert ok.status_code == 200
            wrong = client.get("/api/v1/meta", headers={"X-Api-Token": "nope-nope-nope-nope"})
            assert wrong.status_code == 401
    finally:
        monkeypatch.delenv("THREATSIGHT_API_TOKEN", raising=False)
        get_settings.cache_clear()


def test_auditor_cannot_mutate() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/systems",
            headers={"X-Actor": "auditor", "X-Role": "auditor"},
            json={"name": "blocked", "owner": "audit", "lifecycle": "design", "environment": "lab"},
        )
    assert response.status_code == 403


def test_invalid_role_rejected() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/meta", headers={"X-Role": "superuser"})
    assert response.status_code == 400


def test_ops_config_redacts_secrets() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/ops/config")
    assert response.status_code == 200
    body = response.json()
    assert body["database_url"] == "[redacted]"
    assert body["openai_api_key"] == "[redacted]"
    assert body["api_token"] == "[redacted]"
    assert "changeme-dev-only" not in str(body)
    assert body["legal_compliance_claim"] is False
    assert "COMPLIANT" not in response.text


def test_ops_checklist_is_honest() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/ops/checklist")
    assert response.status_code == 200
    body = response.json()
    ids = {item["id"] for item in body["items"]}
    assert "sandbox_default" in ids
    assert "no_attack_engine" in ids
    assert "demo_sidecars_unpublished" in ids
    assert "no_legal_claim" in ids
    assert "secrets_not_in_image" in ids
    assert body["legal_compliance_claim"] is False


def test_openapi_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREATSIGHT_OPENAPI_ENABLED", "false")
    get_settings.cache_clear()
    try:
        local = create_app()
        with TestClient(local) as client:
            assert client.get("/docs").status_code == 404
            assert client.get("/openapi.json").status_code == 404
    finally:
        monkeypatch.delenv("THREATSIGHT_OPENAPI_ENABLED", raising=False)
        get_settings.cache_clear()

def test_production_configuration_fails_closed() -> None:
    from threatsight_api.config import Settings

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
        sandbox_default=True,
        openapi_enabled=False,
    )
    safe.validate_runtime_security()


def test_authenticated_identity_ignores_spoofed_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import FastAPI
    from threatsight_api.authz import AuthzMiddleware

    token = "server-secret-token-with-at-least-32-chars"
    monkeypatch.setenv("THREATSIGHT_API_TOKEN", token)
    monkeypatch.setenv("THREATSIGHT_API_TOKEN_SUBJECT", "trusted-proxy")
    monkeypatch.setenv("THREATSIGHT_API_TOKEN_ROLE", "auditor")
    get_settings.cache_clear()
    local = FastAPI()
    local.add_middleware(AuthzMiddleware)

    @local.get("/api/whoami")
    async def whoami(request: Request) -> dict:
        return {"actor": request.state.actor, "role": request.state.role}

    try:
        with TestClient(local) as client:
            response = client.get(
                "/api/whoami",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Actor": "attacker",
                    "X-Role": "admin",
                },
            )
        assert response.status_code == 200
        assert response.json() == {"actor": "trusted-proxy", "role": "auditor"}
    finally:
        for name in (
            "THREATSIGHT_API_TOKEN",
            "THREATSIGHT_API_TOKEN_SUBJECT",
            "THREATSIGHT_API_TOKEN_ROLE",
        ):
            monkeypatch.delenv(name, raising=False)
        get_settings.cache_clear()
