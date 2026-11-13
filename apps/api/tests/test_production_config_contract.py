"""Phase 3F production / pilot configuration contract."""

from __future__ import annotations

from pathlib import Path

import pytest
from threatsight_api.config import Settings, get_settings


@pytest.fixture(autouse=True)
def _clear_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _oidc_kwargs() -> dict:
    return {
        "env": "production",
        "auth_mode": "oidc",
        "oidc_issuer": "https://login.example/realms/threatsight",
        "oidc_audience": "threatsight-api",
        "oidc_client_id": "threatsight",
        "oidc_authorization_endpoint": "https://login.example/realms/threatsight/protocol/openid-connect/auth",
        "oidc_token_endpoint": "https://login.example/realms/threatsight/protocol/openid-connect/token",
        "oidc_jwks_uri": "https://login.example/realms/threatsight/protocol/openid-connect/certs",
        "oidc_redirect_uri": "https://threatsight.example/api/v1/auth/callback",
        "database_url": "postgresql+psycopg://threatsight:strong-secret@db.example:5432/threatsight",
        "cors_origins": "https://threatsight.example",
        "web_origins": "https://threatsight.example",
        "public_origin": "https://threatsight.example",
        "openapi_enabled": False,
        "allow_synthetic_loaders": False,
    }


def test_pilot_compose_requires_public_origin() -> None:
    with pytest.raises(ValueError, match="PUBLIC_ORIGIN"):
        Settings(
            **{**_oidc_kwargs(), "deployment_profile": "pilot-compose", "public_origin": ""}
        ).validate_runtime_security()


def test_pilot_compose_accepts_oidc() -> None:
    Settings(**{**_oidc_kwargs(), "deployment_profile": "pilot-compose"}).validate_runtime_security()


def test_pilot_kubernetes_rejects_bundled_postgres_hostname() -> None:
    with pytest.raises(ValueError, match="external PostgreSQL"):
        Settings(
            **{
                **_oidc_kwargs(),
                "deployment_profile": "pilot-kubernetes",
                "database_url": "postgresql+psycopg://threatsight:strong-secret@postgres:5432/threatsight",
            }
        ).validate_runtime_security()


def test_secret_file_loads_and_rejects_world_readable(tmp_path: Path) -> None:
    secret = tmp_path / "db_url"
    secret.write_text(
        "postgresql+psycopg://threatsight:strong-secret@db.example:5432/threatsight",
        encoding="utf-8",
    )
    secret.chmod(0o600)
    settings = Settings(
        **{
            **_oidc_kwargs(),
            "deployment_profile": "pilot-compose",
            "database_url": "postgresql+psycopg://threatsight:changeme-dev-only@postgres:5432/threatsight",
            "database_url_file": str(secret),
        }
    )
    settings.validate_runtime_security()
    assert "strong-secret" in settings.database_url
    assert "changeme-dev-only" not in settings.database_url

    secret.chmod(0o644)
    with pytest.raises(ValueError, match="group/world-readable"):
        Settings(
            **{
                **_oidc_kwargs(),
                "deployment_profile": "pilot-compose",
                "database_url_file": str(secret),
            }
        )


def test_default_password_rejected() -> None:
    with pytest.raises(ValueError, match="development database password"):
        Settings(
            **{
                **_oidc_kwargs(),
                "deployment_profile": "reference",
                "database_url": "postgresql+psycopg://threatsight:changeme-dev-only@postgres:5432/threatsight",
                "public_origin": "",
                "web_origins": "",
                "allow_synthetic_loaders": True,
            }
        ).validate_runtime_security()
