from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine.url import make_url

from threatsight_api.config import get_settings
from threatsight_api.db import run_migrations
from threatsight_api.main import app
from threatsight_api.threats.catalog import ADVISORIES, CATALOG_VERSION, CTRL002_TECHNIQUES, TECHNIQUES, THREATS

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}

pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")

HEADERS = {"X-Actor": "operator"}


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_intel_bootstrap_map_ingest_and_provenance(client: TestClient) -> None:
    assurance = client.post("/api/v1/assurance/demo/bootstrap", headers=HEADERS)
    assert assurance.status_code == 200, assurance.text
    control_id = assurance.json()["control_id"]
    system_id = assurance.json()["system_id"]
    prior = client.get(f"/api/v1/controls/{control_id}")
    assert prior.status_code == 200
    prior_status = prior.json()["assurance_status"]

    boot = client.post("/api/v1/threats/demo/bootstrap", headers=HEADERS)
    assert boot.status_code == 200, boot.text
    body = boot.json()
    assert body["catalog_complete"] is False
    assert body["legal_compliance_claim"] is False
    assert body["autonomous_attack"] is False
    assert body["exploitation_engine"] is False
    assert body["unrestricted_crawl"] is False
    assert body["news_mutates_assurance"] is False
    assert body["threats"] == len(THREATS)
    assert body["techniques"] == len(TECHNIQUES)
    assert body["advisories"] == len(ADVISORIES)
    assert body["control_id"] == control_id
    for key in CTRL002_TECHNIQUES:
        assert key in body["mapped_techniques"]
    assert "owasp_llm08:AUTH-01" in body["suggested_tests"]

    after = client.get(f"/api/v1/controls/{control_id}").json()
    assert after["assurance_status"] == prior_status
    assert after["assurance_status"] != "COMPLIANT"

    again = client.post("/api/v1/threats/demo/bootstrap", headers=HEADERS)
    assert again.status_code == 200, again.text
    assert set(again.json()["mapped_techniques"]) == set(body["mapped_techniques"])

    status = client.get("/api/v1/threats/status").json()
    assert status["catalog_complete"] is False
    assert status["legal_compliance_claim"] is False
    assert status["llm_is_intel_authority"] is False
    assert status["unrestricted_crawl"] is False
    assert status["autonomous_attack"] is False
    assert status["technique_count"] == len(TECHNIQUES)
    assert "COMPLIANT" not in str(status)

    threats = client.get("/api/v1/threats")
    assert threats.status_code == 200
    keys = {item["key"] for item in threats.json()}
    assert keys == {item.key for item in THREATS}
    assert all(item["legal_compliance_claim"] is False for item in threats.json())

    tool_abuse = client.get("/api/v1/threats/tool_abuse")
    assert tool_abuse.status_code == 200, tool_abuse.text
    llm08 = next(item for item in tool_abuse.json()["techniques"] if item["key"] == "owasp_llm08")
    assert llm08["mapped"] is True
    assert llm08["locator"].startswith("https://")
    assert llm08["catalog_version"] == CATALOG_VERSION
    assert llm08["coverage_status"] != "COMPLIANT"

    detail = client.get("/api/v1/threats/tool_abuse/techniques/owasp_llm08")
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    assert payload["legal_compliance_claim"] is False
    assert any(item["id"] == control_id for item in payload["controls"])
    assert any(item["id"] == system_id for item in payload["systems"])
    assert any(item["scenario_key"] == "AUTH-01" and item["executes"] is False for item in payload["suggested_tests"])
    assert payload["locator"].startswith("https://")

    duplicate = client.post(
        "/api/v1/threats/tool_abuse/techniques/owasp_llm08/control-mappings",
        headers=HEADERS,
        json={"control_id": control_id, "note": "dup"},
    )
    assert duplicate.status_code == 409

    leakage = client.get("/api/v1/threats/data_leakage")
    assert leakage.status_code == 200
    llm06 = next(item for item in leakage.json()["techniques"] if item["key"] == "owasp_llm06")
    if not llm06["mapped"]:
        assert llm06["coverage_status"] == "EVIDENCE_REQUIRED"

    extra = client.post(
        "/api/v1/threats/ingest",
        headers=HEADERS,
        json={
            "key": f"lab-extra-{uuid.uuid4().hex[:8]}",
            "title": "Lab extra advisory",
            "summary": "Informational extra advisory mapped to an existing technique.",
            "locator": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "source_kind": "lab",
            "technique_keys": ["owasp_llm06"],
        },
    )
    assert extra.status_code == 200, extra.text
    assert extra.json()["unrestricted_crawl"] is False
    assert extra.json()["news_mutates_assurance"] is False
    still = client.get(f"/api/v1/controls/{control_id}").json()
    assert still["assurance_status"] == prior_status

    blocked = client.post(
        "/api/v1/threats/ingest",
        headers=HEADERS,
        json={
            "key": "lab-crawl",
            "title": "Should not crawl",
            "summary": "Informational payload that tries to crawl.",
            "locator": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "source_kind": "lab",
            "technique_keys": ["owasp_llm06"],
            "crawl": True,
        },
    )
    assert blocked.status_code == 400

    existing = client.post(
        "/api/v1/threats/ingest",
        headers=HEADERS,
        json={
            "key": "owasp-llm-top10",
            "title": "OWASP GenAI LLM Top 10",
            "summary": "Curated index of OWASP GenAI LLM Top 10 topics. Informational catalog ingest, not a live crawl.",
            "locator": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "source_kind": "owasp",
            "technique_keys": ["owasp_llm01"],
        },
    )
    assert existing.status_code == 409

    forbidden = client.post(
        "/api/v1/threats/ingest",
        headers={"X-Actor": "   "},
        json={
            "key": "lab-noperm",
            "title": "Lab extra advisory",
            "summary": "Informational extra advisory mapped to an existing technique.",
            "locator": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "source_kind": "lab",
            "technique_keys": ["owasp_llm06"],
        },
    )
    assert forbidden.status_code == 400

    advisories = client.get("/api/v1/threats/advisories")
    assert advisories.status_code == 200
    assert any(item["key"] == "lab-unauthorized-tool" for item in advisories.json())
    assert all(item["locator"].startswith("https://") for item in advisories.json())

    dash = client.get("/api/v1/dashboard").json()
    assert dash["threats"]["technique_count"] >= len(TECHNIQUES)
    assert dash["threats"]["legal_compliance_claim"] is False
    assert dash["threats"]["catalog_complete"] is False
    assert dash["threats"]["mapped_techniques"] >= len(CTRL002_TECHNIQUES)
    assert "COMPLIANT" not in client.get("/api/v1/dashboard").text

    unknown = client.get("/api/v1/threats/not_a_threat")
    assert unknown.status_code == 404


def test_intel_migration_tables() -> None:
    settings = get_settings()
    url = make_url(settings.database_url)
    admin = url.set(database="postgres")
    db_name = f"ts_m7_{uuid.uuid4().hex[:8]}"
    original = os.environ.get("THREATSIGHT_DATABASE_URL", url.render_as_string(hide_password=False))
    test_url = url.set(database=db_name).render_as_string(hide_password=False)
    admin_engine = create_engine(admin, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{db_name}"'))
    try:
        os.environ["THREATSIGHT_DATABASE_URL"] = test_url
        get_settings.cache_clear()
        run_migrations(get_settings())
        engine = create_engine(test_url)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert "intel_threats" in tables
        assert "intel_techniques" in tables
        assert "intel_advisories" in tables
        assert "intel_technique_controls" in tables
        assert "intel_technique_tests" in tables
        columns = {item["name"] for item in inspector.get_columns("intel_techniques")}
        engine.dispose()
        assert "locator" in columns
        assert "catalog_version" in columns
        assert "informational_only" in columns
    finally:
        os.environ["THREATSIGHT_DATABASE_URL"] = original
        get_settings.cache_clear()
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
        admin_engine.dispose()
