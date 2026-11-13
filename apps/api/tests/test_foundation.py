import os

from fastapi.testclient import TestClient

from threatsight_api.main import app

LIVE_DB = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}


def test_health() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "threatsight-api"
    assert body["milestone"] == "M15"
    assert "X-Request-ID" in response.headers


def test_ready_without_database() -> None:
    if LIVE_DB:
        with TestClient(app) as client:
            response = client.get("/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        return
    with TestClient(app) as client:
        response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["detail"]["status"] == "unavailable"


def test_meta() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/meta")
    assert response.status_code == 200
    body = response.json()
    assert body["product"] == "ThreatSight"
    assert body["milestone"] == "M15"
    assert body["assurance_loop"][0] == "requirement"
    assert body["assurance_loop"][-1] == "assurance"


def test_security_status() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/security/status")
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox_default"] is True
    assert body["kill_switch"] is False
    assert body["execution_engine"] == "ctrl002_tool_authorization"
    assert body["llm_is_verdict_authority"] is False
    assert body["document_content_is_untrusted"] is True
    assert body["extraction_provider"] == "heuristic"
    assert body["llm_may_authorize_fetch"] is False
    assert body["unrestricted_crawl"] is False
    assert body["llm_is_coverage_authority"] is False
    assert body["framework_catalog_complete"] is False
    assert body["llm_is_intel_authority"] is False
    assert body["intel_catalog_complete"] is False
    assert body["autonomous_attack"] is False
    assert body["exploitation_engine"] is False
    assert body["auth_mode"] == "lab_open"
    assert body["api_token_configured"] is False
    assert body["openapi_enabled"] is True
    assert body["llm_authors_executive_summary"] is False
    assert body["showcase_synthetic_labelled"] is True
    assert body["llm_may_authorize"] is False
    assert body["runtime_firewall"] is False
