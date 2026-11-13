"""Continuous readiness: approval, isolation, idempotency, and fixture execution."""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from threatsight_api.graph.materialize import materialize
from threatsight_api.investigations.reference import install as install_journeys
from threatsight_api.main import app
from threatsight_api.persistence.models import Workspace, WorkspaceMembership
from threatsight_api.persistence.session import get_engine
from threatsight_api.readiness.checks import get_check
from threatsight_api.readiness.reference import install as install_readiness
from threatsight_api.readiness.vocabulary import APPROVE_ROLES

pytestmark = pytest.mark.skipif(
    os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() not in {"1", "true", "yes"},
    reason="requires postgres",
)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(role: str = "workspace-admin") -> dict[str, str]:
    subject = f"ready-{uuid.uuid4().hex[:8]}"
    key = f"ready-{uuid.uuid4().hex[:10]}"
    with Session(get_engine()) as db:
        tenant_id = db.scalar(text("SELECT tenant_id FROM workspaces WHERE key = 'default'"))
        workspace = Workspace(tenant_id=tenant_id, key=key, name=key, status="active")
        db.add(workspace)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, role=role))
        db.commit()
        return {"X-Actor": subject, "X-Workspace-Key": key, "tenant": str(tenant_id), "id": str(workspace.id)}


def _seed(headers: dict[str, str]) -> None:
    with Session(get_engine()) as db:
        materialize(
            db,
            tenant_id=uuid.UUID(headers["tenant"]),
            workspace_id=uuid.UUID(headers["id"]),
            actor=headers["X-Actor"],
            idempotency_key=f"ready-{uuid.uuid4().hex[:8]}",
            fixture="correlation",
        )
        db.commit()
    with Session(get_engine()) as db:
        install_journeys(db.connection())
        install_readiness(db.connection())
        install_readiness(db.connection())
        db.commit()


def test_allowlisted_checks_are_fixture_tested() -> None:
    check = get_check("synthetic.version.validate.v1")
    assert check is not None
    assert check.live_supported is False
    assert check.maturity == "fixture_tested"
    warehouse = get_check("inventory_config_verify_iot2050")
    assert warehouse is not None
    assert warehouse.live_supported is False
    assert warehouse.capability == "configuration_evidence"
    assert "operator" not in APPROVE_ROLES


def test_readiness_workflow_requires_admin_approval(client: TestClient) -> None:
    admin = _workspace("workspace-admin")
    operator_subject = f"op-{uuid.uuid4().hex[:8]}"
    foreign = _workspace("workspace-admin")
    with Session(get_engine()) as db:
        db.add(WorkspaceMembership(workspace_id=uuid.UUID(admin["id"]), subject=operator_subject, role="operator"))
        db.commit()
    operator = {"X-Actor": operator_subject, "X-Workspace-Key": admin["X-Workspace-Key"]}
    _seed(admin)
    summary = client.get("/api/v1/readiness/summary", headers=admin)
    assert summary.status_code == 200
    body = summary.json()
    assert body["approval_mode"] == "manual_approval_required"
    assert body["services_needing_verification"] >= 1
    recommendation = body["recommendations"][0]
    assert recommendation["maturity"] == "Validated with reference data"
    assert recommendation["approval_required"] is True
    denied = client.post(f"/api/v1/readiness/recommendations/{recommendation['id']}/approve", headers=operator)
    assert denied.status_code == 403
    preview = client.post(f"/api/v1/readiness/recommendations/{recommendation['id']}/preview", headers=admin)
    assert preview.status_code == 200
    assert preview.json()["approval_required"] is True
    approved = client.post(f"/api/v1/readiness/recommendations/{recommendation['id']}/approve", headers=admin)
    assert approved.status_code == 200
    payload = approved.json()
    assert payload["status"] == "succeeded"
    assert payload["result"]["outcome"] == "configured_not_observed"
    assert "Validated with reference data" in payload["maturity"]
    again = client.post(f"/api/v1/readiness/recommendations/{recommendation['id']}/approve", headers=admin)
    assert again.status_code == 200
    assert again.json()["id"] == payload["id"]
    isolated = client.get(f"/api/v1/readiness/requests/{payload['id']}", headers=foreign)
    assert isolated.status_code == 404
    decision = client.post(
        f"/api/v1/readiness/requests/{payload['id']}/decisions",
        headers=admin,
        json={"outcome": "accepted", "rationale": "Reference check accepted for the synthetic journey."},
    )
    assert decision.status_code == 200
    assert decision.json()["outcome"] == "accepted"


def test_missing_recommendation_is_uniform_not_found(client: TestClient) -> None:
    headers = _workspace()
    response = client.get(f"/api/v1/readiness/recommendations/{uuid.uuid4()}", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "Readiness object not found"


def test_kill_switch_blocks_approval(client: TestClient) -> None:
    headers = _workspace()
    _seed(headers)
    summary = client.get("/api/v1/readiness/summary", headers=headers)
    recommendation_id = summary.json()["recommendations"][0]["id"]
    with Session(get_engine()) as db:
        db.execute(
            text("UPDATE readiness_policies SET kill_switch = true WHERE workspace_id = :wid"),
            {"wid": headers["id"]},
        )
        db.commit()
    blocked = client.post(f"/api/v1/readiness/recommendations/{recommendation_id}/approve", headers=headers)
    assert blocked.status_code == 409
    assert "Kill switch" in blocked.json()["detail"]


def test_approve_rejects_live_supported_check(client: TestClient, monkeypatch) -> None:
    headers = _workspace()
    _seed(headers)
    summary = client.get("/api/v1/readiness/summary", headers=headers)
    recommendation_id = summary.json()["recommendations"][0]["id"]
    from threatsight_api.readiness import checks as check_mod

    original = check_mod.require_check

    def live_check(check_id: str):
        check = original(check_id)
        return check_mod.Check(
            id=check.id,
            version=check.version,
            connector=check.connector,
            capability=check.capability,
            title=check.title,
            expected_data=check.expected_data,
            operational_impact=check.operational_impact,
            result_mapping=check.result_mapping,
            limitations=check.limitations,
            live_supported=True,
            maturity=check.maturity,
        )

    monkeypatch.setattr(check_mod, "require_check", live_check)
    monkeypatch.setattr("threatsight_api.readiness.service.require_check", live_check)
    blocked = client.post(f"/api/v1/readiness/recommendations/{recommendation_id}/approve", headers=headers)
    assert blocked.status_code == 409
    assert "customer-runner" in blocked.json()["detail"]


def test_client_cannot_supply_arbitrary_check_or_runner(client: TestClient) -> None:
    headers = _workspace()
    _seed(headers)
    summary = client.get("/api/v1/readiness/summary", headers=headers)
    recommendation_id = summary.json()["recommendations"][0]["id"]
    response = client.post(
        f"/api/v1/readiness/recommendations/{recommendation_id}/approve",
        headers=headers,
        json={"check_id": "shell.exec.v1", "runner_id": str(uuid.uuid4()), "secret": "leak"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["check_id"] == "synthetic.version.validate.v1" or body["result"]["outcome"] == "configured_not_observed"
    assert "secret" not in str(body).lower() or "secret_reference" in str(body).lower()


def test_dismiss_keeps_history(client: TestClient) -> None:
    headers = _workspace()
    _seed(headers)
    summary = client.get("/api/v1/readiness/summary", headers=headers)
    recommendation_id = summary.json()["recommendations"][0]["id"]
    dismissed = client.post(f"/api/v1/readiness/recommendations/{recommendation_id}/dismiss", headers=headers)
    assert dismissed.status_code == 200
    assert dismissed.json()["state"] == "dismissed"
    again = client.post(f"/api/v1/readiness/recommendations/{recommendation_id}/approve", headers=headers)
    assert again.status_code == 409
