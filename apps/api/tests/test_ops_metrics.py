"""Safe ops metrics endpoint — no secrets in payload."""

from __future__ import annotations

from fastapi.testclient import TestClient
from threatsight_api.config import get_settings
from threatsight_api.main import app


def test_ops_metrics_payload_has_no_secrets() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/ops/metrics")
    assert response.status_code in {200, 401, 403}
    if response.status_code == 200:
        body = response.text.lower()
        assert "threatsight_up" in body
        assert "changeme-dev-only" not in body
        assert "client_secret" not in body
        assert "begin private" not in body


def test_ops_metrics_public_flag_emits_openmetrics(monkeypatch) -> None:
    monkeypatch.setenv("THREATSIGHT_OPS_METRICS_PUBLIC", "true")
    get_settings.cache_clear()
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/ops/metrics")
        assert response.status_code == 200
        assert "threatsight_up" in response.text
        assert "changeme" not in response.text.lower()
    finally:
        monkeypatch.delenv("THREATSIGHT_OPS_METRICS_PUBLIC", raising=False)
        get_settings.cache_clear()
