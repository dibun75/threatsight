from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from threatsight_api.config import Settings
from threatsight_api.runner import control_plane_base, load_runner_credential

ROOT = Path(__file__).resolve().parents[3]


def test_blank_or_unknown_auth_mode_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(auth_mode=" ")
    with pytest.raises(ValidationError):
        Settings(auth_mode="header")


def test_production_rejects_reference_host_authentication() -> None:
    settings = Settings(
        env="production",
        auth_mode="development",
        database_url="postgresql+psycopg://threatsight:not-a-placeholder@postgres/threatsight",
        cors_origins="https://threatsight.io",
        sandbox_default=True,
    )
    with pytest.raises(ValueError, match="oidc"):
        settings.validate_runtime_security()


def test_control_plane_refuses_http_outside_development() -> None:
    assert control_plane_base("http://threatsight-api:8000/") == "http://threatsight-api:8000"
    with pytest.raises(ValueError, match="HTTPS"):
        control_plane_base("http://threatsight.example", require_tls=True)
    assert control_plane_base("https://threatsight.example", require_tls=True) == "https://threatsight.example"


def test_runner_credential_comes_from_a_file(tmp_path: Path) -> None:
    path = tmp_path / "credential"
    path.write_text("synthetic-runner-credential\n", encoding="utf-8")
    loaded = load_runner_credential(
        {"THREATSIGHT_ENV": "production", "THREATSIGHT_RUNNER_CREDENTIAL_FILE": str(path)}
    )
    assert loaded == "synthetic-runner-credential"
    with pytest.raises(ValueError):
        load_runner_credential({"THREATSIGHT_ENV": "production", "THREATSIGHT_RUNNER_CREDENTIAL": "not-from-a-file"})


def test_encrypted_backup_round_trip_uses_a_disposable_key(tmp_path: Path) -> None:
    key_dir = tmp_path / "keys"
    out_dir = tmp_path / "backups"
    key_dir.mkdir()
    out_dir.mkdir()
    key = key_dir / "disposable.key"
    key.write_bytes(os.urandom(32))
    source = tmp_path / "source.dump"
    source.write_bytes(b"PGDMP-synthetic-drill")
    encrypted = out_dir / "drill.enc"
    manifest = out_dir / "drill.enc.manifest.json"
    script = ROOT / "scripts" / "encrypted_backup.py"
    subprocess.run(
        [sys.executable, str(script), "encrypt", "--input", str(source), "--output", str(encrypted), "--key", str(key), "--manifest", str(manifest), "--revision", "0016", "--release", "drill"],
        check=True,
        cwd=ROOT,
    )
    restored = tmp_path / "restored.dump"
    subprocess.run(
        [sys.executable, str(script), "decrypt", "--input", str(encrypted), "--output", str(restored), "--key", str(key), "--manifest", str(manifest)],
        check=True,
        cwd=ROOT,
    )
    assert restored.read_bytes() == source.read_bytes()
    recorded = json.loads(manifest.read_text(encoding="utf-8"))
    assert recorded["encryption"] == "AES-256-GCM"
    assert recorded["off_host"] is False
    assert "disposable" not in json.dumps(recorded)
    refused = subprocess.run(
        [sys.executable, str(script), "encrypt", "--input", str(source), "--output", str(key_dir / "beside.enc"), "--key", str(key)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert refused.returncode != 0


LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_execution_status_is_redacted_and_access_headers_are_ignored() -> None:
    from fastapi.testclient import TestClient

    from threatsight_api.main import app

    with TestClient(app) as client:
        denied = client.get(
            "/api/v1/ops/execution",
            headers={"X-Actor": "web-proxy", "X-Role": "operator", "Cf-Access-Jwt-Assertion": "not-a-jwt"},
        )
        assert denied.status_code == 403
        allowed = client.get(
            "/api/v1/ops/execution",
            headers={
                "X-Actor": "operator",
                "X-Role": "workspace-admin",
                "Cf-Access-Authenticated-User-Email": "other@example.com",
            },
        )
        assert allowed.status_code == 200
        body = allowed.json()
        assert body["worker_required"] is False
        assert "configuration" not in body
        assert "token_hash" not in json.dumps(body)
        workspace = client.get(
            "/api/v1/radar/workspace",
            headers={
                "X-Actor": "operator",
                "X-Role": "workspace-admin",
                "Cf-Access-Authenticated-User-Email": "other@example.com",
            },
        )
        assert workspace.json()["subject"] == "operator"
