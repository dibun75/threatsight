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

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}

pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_discovery_register_scan_review_map_and_duplicates(client: TestClient) -> None:
    headers = {"X-Actor": "operator"}
    assert client.post(
        "/api/v1/discovery/sources",
        headers=headers,
        json={"url": "http://127.0.0.1:8091/", "owner": "operator"},
    ).status_code == 400
    assert client.post(
        "/api/v1/discovery/sources",
        headers=headers,
        json={"url": "file:///etc/passwd", "owner": "operator"},
    ).status_code == 400
    assert client.post(
        "/api/v1/discovery/sources",
        headers=headers,
        json={"url": "http://evil.example/", "owner": "operator"},
    ).status_code == 403

    boot = client.post("/api/v1/discovery/demo/bootstrap", headers=headers)
    assert boot.status_code == 200, boot.text
    source_id = boot.json()["source_id"]
    assert boot.json()["synthetic"] is True

    again = client.post(
        "/api/v1/discovery/sources",
        headers=headers,
        json={"url": boot.json()["url"], "owner": "operator"},
    )
    assert again.status_code == 409

    denied = client.post(
        f"/api/v1/discovery/sources/{source_id}/scans",
        headers=headers,
        json={"confirm_execution": False},
    )
    assert denied.status_code == 400

    scan = client.post(
        f"/api/v1/discovery/sources/{source_id}/scans",
        headers=headers,
        json={"confirm_execution": True},
    )
    assert scan.status_code == 201, scan.text
    body = scan.json()
    assert body["status"] in {"completed", "unchanged"}
    assert body["robots_checked"] is True
    assert body["content_hash"]
    assert len(body["content_hash"]) == 64

    assets = client.get("/api/v1/discovery/assets").json()
    assert assets
    assert all("demo-site" in item["url"] for item in assets)
    signals = client.get("/api/v1/discovery/signals").json()
    kinds = {item["signal_kind"] for item in signals}
    assert "ai_usage_disclosure" in kinds
    assert "model_provider_reference" in kinds
    assert "privacy_security_doc" in kinds
    assert "governance_statement" in kinds
    dumped = str(signals)
    assert "COMPLIANT" not in dumped
    pending = [item for item in signals if item["review_status"] == "pending"]
    target = pending[0] if pending else signals[0]
    assert target["page_url"]
    assert target["content_hash"]
    assert target["quote"]

    if target["review_status"] == "pending":
        approved = client.post(
            f"/api/v1/discovery/signals/{target['id']}/review",
            headers=headers,
            json={"decision": "approved"},
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["evidence_id"]
        evidence_id = approved.json()["evidence_id"]
    else:
        evidence_id = target["evidence_id"]
        assert evidence_id
    evidence = client.get(f"/api/v1/evidence/{evidence_id}")
    assert evidence.status_code == 200
    record = evidence.json()
    assert record["status"] == "accepted"
    assert target["page_url"] in (record["provenance"] or "")
    assert target["content_hash"] in (record["provenance"] or "")
    assert record["envelope"]["legal_compliance_claim"] is False
    assert "COMPLIANT" not in evidence.text

    assurance = client.post("/api/v1/assurance/demo/bootstrap", headers=headers)
    assert assurance.status_code == 200, assurance.text
    control_id = assurance.json()["control_id"]
    mapped = client.post(
        f"/api/v1/discovery/signals/{target['id']}/map-control",
        headers=headers,
        json={"control_id": control_id},
    )
    assert mapped.status_code in {200, 409}, mapped.text

    control = client.get(f"/api/v1/controls/{control_id}")
    assert control.json()["assurance_status"] != "COMPLIANT"
    assert "COMPLIANT" not in control.text

    repeat = client.post(
        f"/api/v1/discovery/sources/{source_id}/scans",
        headers=headers,
        json={"confirm_execution": True},
    )
    assert repeat.status_code == 201, repeat.text
    assert repeat.json()["status"] == "unchanged"
    assert repeat.json()["content_hash"] == body["content_hash"]

    internal = client.post(
        "/api/v1/discovery/sources",
        headers=headers,
        json={
            "url": "http://demo-site:8091/internal",
            "owner": "operator",
            "title": "blocked path",
            "refresh_authorization": True,
        },
    )
    assert internal.status_code == 201, internal.text
    internal_id = internal.json()["id"]
    blocked = client.post(
        f"/api/v1/discovery/sources/{internal_id}/scans",
        headers=headers,
        json={"confirm_execution": True},
    )
    assert blocked.status_code == 201, blocked.text
    assert blocked.json()["status"] == "blocked"

    dash = client.get("/api/v1/dashboard").json()
    assert dash["discovery"]["sources"] >= 1
    assert dash["discovery"]["assets"] >= 1
    status = client.get("/api/v1/discovery/status").json()
    assert status["llm_may_authorize_fetch"] is False
    assert status["unrestricted_crawl"] is False


def test_discovery_migration_tables() -> None:
    settings = get_settings()
    url = make_url(settings.database_url)
    admin = url.set(database="postgres")
    db_name = f"ts_m5_{uuid.uuid4().hex[:8]}"
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
        tables = set(inspect(engine).get_table_names())
        engine.dispose()
        assert "discovery_sources" in tables
        assert "discovery_scans" in tables
        assert "discovered_assets" in tables
        assert "discovery_signals" in tables
    finally:
        os.environ["THREATSIGHT_DATABASE_URL"] = original
        get_settings.cache_clear()
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
        admin_engine.dispose()
