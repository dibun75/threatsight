from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from threatsight_api.config import get_settings
from threatsight_api.db import run_migrations
from threatsight_api.main import app
from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}

pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_ctrl002_fail_remediate_retest_and_benign(client: TestClient) -> None:
    headers = {"X-Actor": "operator"}
    boot = client.post("/api/v1/assurance/demo/bootstrap", headers=headers)
    assert boot.status_code == 200, boot.text
    assert "AUTH-01" in boot.json()["scenarios"]

    denied = client.post(
        "/api/v1/assurance/runs",
        headers=headers,
        json={"scenario_key": "AUTH-01", "confirm_execution": False},
    )
    assert denied.status_code == 400

    fail_run = client.post(
        "/api/v1/assurance/runs",
        headers=headers,
        json={"scenario_key": "AUTH-01", "confirm_execution": True},
    )
    assert fail_run.status_code == 201, fail_run.text
    body = fail_run.json()
    assert body["verdict"] == "FAIL"
    assert body["reason_code"] == "UNAUTHORIZED_IMPACT_COMPLETED"
    assert body["evaluator"] == "deterministic_policy"
    assert body["legal_compliance_claim"] is False
    assert body["observation"]["completed_side_effect"] == "order_cancelled"
    assert body["narration"] == "I cannot cancel orders for other customers."
    assert body["finding_id"]
    evidence = client.get(f"/api/v1/evidence/{body['evidence_id']}")
    assert evidence.status_code == 200
    assert evidence.json()["integrity_hash"]
    assert evidence.json()["envelope"]["completed_side_effect"] == "order_cancelled"

    finding = client.get(f"/api/v1/findings/{body['finding_id']}")
    assert finding.status_code == 200
    assert finding.json()["severity"] == "high"
    assert finding.json()["status"] == "open"

    benign = client.post(
        "/api/v1/assurance/runs",
        headers=headers,
        json={"scenario_key": "AUTH-02", "confirm_execution": True},
    )
    assert benign.status_code == 201, benign.text
    assert benign.json()["verdict"] == "PASS"
    assert benign.json()["reason_code"] == "AUTHORIZED_ACTION_COMPLETED"

    remediated = client.post(f"/api/v1/findings/{body['finding_id']}/remediate", headers=headers)
    assert remediated.status_code == 201, remediated.text
    assert remediated.json()["action"] == "enable_gateway_authorization"

    retest = client.post(
        "/api/v1/assurance/runs",
        headers=headers,
        json={
            "scenario_key": "AUTH-01",
            "confirm_execution": True,
            "parent_run_id": body["id"],
        },
    )
    assert retest.status_code == 201, retest.text
    assert retest.json()["verdict"] == "PASS"
    assert retest.json()["reason_code"] == "UNAUTHORIZED_ACTION_BLOCKED"
    assert retest.json()["parent_run_id"] == body["id"]
    assert retest.json()["observation"]["gateway_decision"] == "deny"
    assert retest.json()["observation"]["completed_side_effect"] is None

    resolved = client.get(f"/api/v1/findings/{body['finding_id']}")
    assert resolved.json()["status"] == "resolved"

    control = client.get(f"/api/v1/controls/{boot.json()['control_id']}")
    assert control.json()["latest_verdict"] == "PASS"
    assert control.json()["assurance_status"] == "VALIDATED"

    audit = client.get("/api/v1/audit", params={"entity_type": "assurance_run", "entity_id": body["id"]})
    assert audit.status_code == 200
    assert any(item["action"] == "execute" for item in audit.json())
    retest_audit = client.get("/api/v1/audit", params={"entity_type": "assurance_run", "entity_id": retest.json()["id"]})
    assert any(item["action"] == "retest" for item in retest_audit.json())

    unknown = client.post(
        "/api/v1/assurance/runs",
        headers=headers,
        json={"scenario_key": "AUTH-99", "confirm_execution": True},
    )
    assert unknown.status_code == 400


def test_assurance_migration_tables() -> None:
    settings = get_settings()
    url = make_url(settings.database_url)
    admin = url.set(database="postgres")
    db_name = f"ts_m3_{uuid.uuid4().hex[:8]}"
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
        assert "assurance_runs" in tables
        assert "assurance_targets" in tables
        assert "findings" in tables
        assert "remediations" in tables
    finally:
        os.environ["THREATSIGHT_DATABASE_URL"] = original
        get_settings.cache_clear()
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
        admin_engine.dispose()
