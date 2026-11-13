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


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def test_governance_exit_criteria(client: TestClient) -> None:
    headers = {"X-Actor": "reviewer.alex"}
    ident = f"CTRL-{uuid.uuid4().hex[:8].upper()}"

    system = client.post(
        "/api/v1/systems",
        headers=headers,
        json={
            "name": _unique("agent"),
            "description": "Internal assistant",
            "owner": "platform",
            "team": "assurance",
            "environment": "lab",
            "lifecycle": "draft",
            "risk_classification": "internal",
        },
    )
    assert system.status_code == 201, system.text
    system_id = system.json()["id"]

    requirement = client.post(
        "/api/v1/requirements",
        headers=headers,
        json={
            "title": "Tool authorization",
            "statement": "Unauthorized high-impact tools must be denied outside the model.",
            "source_type": "policy",
            "source_reference": "internal-ai-policy-v1",
            "status": "candidate",
        },
    )
    assert requirement.status_code == 201, requirement.text
    requirement_id = requirement.json()["id"]

    control = client.post(
        "/api/v1/controls",
        headers=headers,
        json={
            "identifier": ident,
            "title": "External tool authorization",
            "objective": "Deny unauthorized cancellation tools.",
            "owner": "security",
            "severity": "high",
            "assurance_status": "EVIDENCE_REQUIRED",
        },
    )
    assert control.status_code == 201, control.text
    control_id = control.json()["id"]
    assert control.json()["version"] == 1

    mapping = client.post(
        f"/api/v1/controls/{control_id}/requirements",
        headers=headers,
        json={
            "requirement_id": requirement_id,
            "rationale": "This control tests the authorization requirement.",
            "provenance": "manual-m1",
        },
    )
    assert mapping.status_code == 201, mapping.text
    duplicate = client.post(
        f"/api/v1/controls/{control_id}/requirements",
        headers=headers,
        json={"requirement_id": requirement_id},
    )
    assert duplicate.status_code == 409

    evidence = client.post(
        "/api/v1/evidence",
        headers=headers,
        json={
            "title": "Manual authorization note",
            "description": "Operator-recorded observation until M3 tests exist.",
            "evidence_type": "manual",
            "owner": "security",
            "status": "submitted",
            "control_ids": [control_id],
            "ai_system_ids": [system_id],
        },
    )
    assert evidence.status_code == 201, evidence.text
    assert control_id in evidence.json()["control_ids"]

    refs = client.get("/api/v1/framework-references")
    assert refs.status_code == 200
    nist = next(item for item in refs.json() if item["framework_key"] == "nist_ai_rmf")
    mapped = client.post(
        f"/api/v1/controls/{control_id}/framework-mappings",
        headers=headers,
        json={"framework_reference_id": nist["id"], "note": "Informational mapping only."},
    )
    assert mapped.status_code == 201, mapped.text
    assert mapped.json()["legal_compliance_claim"] is False
    assert mapped.json()["informational_only"] is True

    review = client.post(
        "/api/v1/reviews",
        headers=headers,
        json={
            "entity_type": "requirement",
            "entity_id": requirement_id,
            "reviewer": "reviewer.alex",
            "decision": "approve",
            "comment": "Accepted as a candidate control driver.",
        },
    )
    assert review.status_code == 201, review.text
    approved = client.get(f"/api/v1/requirements/{requirement_id}")
    assert approved.json()["status"] == "approved"

    status_update = client.patch(
        f"/api/v1/controls/{control_id}",
        headers=headers,
        json={
            "assurance_status": "HUMAN_REVIEW_REQUIRED",
            "assurance_rationale": "Manual evidence attached; technical validation is M3.",
        },
    )
    assert status_update.status_code == 200
    assert status_update.json()["version"] == 2
    assert status_update.json()["assurance_status"] == "HUMAN_REVIEW_REQUIRED"

    assurance = client.get(f"/api/v1/controls/{control_id}/assurance")
    assert assurance.status_code == 200
    body = assurance.json()
    assert body["legal_compliance_claim"] is False
    assert body["latest_technical_verdict"] is None
    assert len(body["requirements"]) == 1
    assert len(body["evidence"]) == 1
    assert len(body["framework_mappings"]) == 1

    audit = client.get("/api/v1/audit", params={"entity_type": "control", "entity_id": control_id})
    assert audit.status_code == 200
    actions = {item["action"] for item in audit.json()}
    assert "create" in actions
    assert "map" in actions
    assert "status_change" in actions


def test_rejects_compliance_status_and_oversized_input(client: TestClient) -> None:
    ident = f"CTRL-{uuid.uuid4().hex[:8].upper()}"
    created = client.post(
        "/api/v1/controls",
        json={
            "identifier": ident,
            "title": "Bound",
            "objective": "Keep input bounded.",
            "owner": "security",
        },
    )
    assert created.status_code == 201
    forbidden = client.patch(
        f"/api/v1/controls/{created.json()['id']}",
        json={"assurance_status": "COMPLIANT"},
    )
    assert forbidden.status_code == 422
    too_long = client.post(
        "/api/v1/systems",
        json={"name": "x" * 201, "owner": "a", "environment": "lab"},
    )
    assert too_long.status_code == 422
    unknown = client.get(f"/api/v1/systems/{uuid.uuid4()}")
    assert unknown.status_code == 404


def test_clean_database_migration() -> None:
    settings = get_settings()
    url = make_url(settings.database_url)
    admin = url.set(database="postgres")
    db_name = f"ts_mig_{uuid.uuid4().hex[:8]}"
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
        assert "findings" in tables
        assert "source_documents" in tables
        assert "document_versions" in tables
        assert "extraction_candidates" in tables
        assert "ai_systems" in tables
        assert "controls" in tables
        assert "evidence_records" in tables
        assert "audit_events" in tables
        assert "framework_references" in tables
    finally:
        os.environ["THREATSIGHT_DATABASE_URL"] = original
        get_settings.cache_clear()
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
        admin_engine.dispose()
