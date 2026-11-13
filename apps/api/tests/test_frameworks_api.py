from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine.url import make_url

from threatsight_api.config import get_settings
from threatsight_api.db import run_migrations
from threatsight_api.frameworks.catalog import CATALOG_ITEMS, CATALOG_VERSION
from threatsight_api.main import app

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}

pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_framework_catalog_map_coverage_and_provenance(client: TestClient) -> None:
    headers = {"X-Actor": "operator"}
    assurance = client.post("/api/v1/assurance/demo/bootstrap", headers=headers)
    assert assurance.status_code == 200, assurance.text
    control_id = assurance.json()["control_id"]

    boot = client.post("/api/v1/frameworks/demo/bootstrap", headers=headers)
    assert boot.status_code == 200, boot.text
    body = boot.json()
    assert body["catalog_complete"] is False
    assert body["legal_compliance_claim"] is False
    assert body["item_count"] == len(CATALOG_ITEMS)
    assert body["control_id"] == control_id
    assert "owasp_genai:LLM08" in body["mapped_references"]

    again = client.post("/api/v1/frameworks/demo/bootstrap", headers=headers)
    assert again.status_code == 200, again.text
    assert set(again.json()["mapped_references"]) == set(body["mapped_references"])

    status = client.get("/api/v1/frameworks/status").json()
    assert status["catalog_complete"] is False
    assert status["legal_compliance_claim"] is False
    assert status["llm_is_coverage_authority"] is False
    assert status["items"] == len(CATALOG_ITEMS)
    assert "COMPLIANT" not in str(status)

    catalogs = client.get("/api/v1/frameworks")
    assert catalogs.status_code == 200
    keys = {item["key"] for item in catalogs.json()}
    assert keys == {"eu_ai_act", "gdpr", "nist_ai_rmf", "iso_42001", "owasp_genai", "mitre_atlas"}
    assert all(item["legal_compliance_claim"] is False for item in catalogs.json())
    assert all(item["catalog_complete"] is False for item in catalogs.json())

    owasp = client.get("/api/v1/frameworks/owasp_genai")
    assert owasp.status_code == 200, owasp.text
    llm08 = next(item for item in owasp.json()["items"] if item["reference_code"] == "LLM08")
    assert llm08["mapped"] is True
    assert llm08["locator"].startswith("https://")
    assert llm08["catalog_version"] == CATALOG_VERSION
    assert llm08["coverage_status"] in {
        "VALIDATED",
        "PARTIALLY_VALIDATED",
        "GAP_DETECTED",
        "EVIDENCE_REQUIRED",
        "HUMAN_REVIEW_REQUIRED",
        "NOT_APPLICABLE",
    }
    assert llm08["coverage_status"] != "COMPLIANT"

    detail = client.get("/api/v1/frameworks/owasp_genai/items/LLM08")
    assert detail.status_code == 200, detail.text
    assert detail.json()["legal_compliance_claim"] is False
    assert any(item["id"] == control_id for item in detail.json()["controls"])

    duplicate = client.post(
        f"/api/v1/controls/{control_id}/framework-mappings",
        headers=headers,
        json={"framework_reference_id": llm08["id"], "note": "dup"},
    )
    assert duplicate.status_code == 409

    unmapped = next(item for item in owasp.json()["items"] if item["reference_code"] == "LLM06")
    if not unmapped["mapped"]:
        assert unmapped["coverage_status"] == "EVIDENCE_REQUIRED"

    dash = client.get("/api/v1/dashboard").json()
    assert dash["frameworks"]["item_count"] >= len(CATALOG_ITEMS)
    assert dash["frameworks"]["legal_compliance_claim"] is False
    assert dash["frameworks"]["catalog_complete"] is False
    assert "COMPLIANT" not in client.get("/api/v1/dashboard").text

    unknown = client.get("/api/v1/frameworks/not_a_framework")
    assert unknown.status_code == 404


def test_framework_migration_columns() -> None:
    settings = get_settings()
    url = make_url(settings.database_url)
    admin = url.set(database="postgres")
    db_name = f"ts_m6_{uuid.uuid4().hex[:8]}"
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
        columns = {item["name"] for item in inspect(engine).get_columns("framework_references")}
        engine.dispose()
        assert "statement" in columns
        assert "source_kind" in columns
        assert "catalog_version" in columns
        assert "informational_only" in columns
    finally:
        os.environ["THREATSIGHT_DATABASE_URL"] = original
        get_settings.cache_clear()
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
        admin_engine.dispose()
