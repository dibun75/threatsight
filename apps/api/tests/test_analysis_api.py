from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatsight_api.analysis.execute import execute
from threatsight_api.config import get_settings
from threatsight_api.graph.materialize import materialize
from threatsight_api.graph.sanitize import GraphFailure
from threatsight_api.main import app
from threatsight_api.persistence.models import AnalysisResult, AnalysisRun, GraphNode, GraphSnapshot, Workspace, WorkspaceMembership
from threatsight_api.persistence.session import get_engine

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires postgres")
FORBIDDEN = ("safe", "secure", "compliant", "compromised", "exploitable", "breached", "protected")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(role: str = "workspace-admin") -> dict[str, str]:
    subject = f"an-{uuid.uuid4().hex[:8]}"
    key = f"an-{uuid.uuid4().hex[:10]}"
    with Session(get_engine()) as db:
        tenant_id = db.scalar(select(Workspace.tenant_id).where(Workspace.key == "default"))
        workspace = Workspace(tenant_id=tenant_id, key=key, name=key, status="active")
        db.add(workspace)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, role=role))
        db.commit()
    return {"X-Actor": subject, "X-Workspace-Key": key}


def _ids(headers: dict[str, str]) -> tuple[uuid.UUID, uuid.UUID]:
    with Session(get_engine()) as db:
        workspace = db.scalar(select(Workspace).where(Workspace.key == headers["X-Workspace-Key"]))
        assert workspace is not None
        return workspace.tenant_id, workspace.id


def _snapshot(headers: dict[str, str], fixture: str = "nordic-retail") -> str:
    tenant_id, workspace_id = _ids(headers)
    with Session(get_engine()) as db:
        row = materialize(
            db,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            actor=headers["X-Actor"],
            idempotency_key=f"graph-{uuid.uuid4().hex[:8]}",
            fixture=fixture,
        )
        return str(row.id)


def test_analysis_api_is_workspace_scoped_and_deterministic(client: TestClient) -> None:
    headers = _workspace()
    other = _workspace()
    operator = _workspace("operator")
    snapshot_id = _snapshot(headers)
    denied = client.post("/api/v1/analysis/runs", headers=operator, json={"snapshot_id": snapshot_id, "idempotency_key": "operator-run-1"})
    assert denied.status_code == 403
    missing = client.post("/api/v1/analysis/runs", headers=headers, json={"snapshot_id": str(uuid.uuid4()), "idempotency_key": "missing-run-01"})
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Analysis object not found"
    foreign = client.post("/api/v1/analysis/runs", headers=other, json={"snapshot_id": snapshot_id, "idempotency_key": "foreign-run-01"})
    assert foreign.status_code == 404
    assert foreign.json()["detail"] == "Analysis object not found"
    injected = client.post(
        "/api/v1/analysis/runs",
        headers=headers,
        json={"snapshot_id": snapshot_id, "idempotency_key": "inject-run-001", "rule": "match all", "depth": 99},
    )
    assert injected.status_code == 422
    created = client.post("/api/v1/analysis/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "nordic-run-001"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["status"] == "completed"
    assert body["is_current"] is True
    assert body["ruleset_version"] == "p2-12.v1"
    again = client.post("/api/v1/analysis/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "nordic-run-001"})
    assert again.json()["id"] == body["id"]
    repeat = client.post("/api/v1/analysis/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "nordic-run-002"})
    assert repeat.json()["id"] == body["id"]
    assert repeat.json()["content_hash"] == body["content_hash"]
    hidden = client.get(f"/api/v1/analysis/results?run_id={body['id']}", headers=other)
    assert hidden.status_code == 404
    results = client.get("/api/v1/analysis/results", headers=headers)
    assert results.status_code == 200
    rows = results.json()
    assert rows
    assert all(item["node_keys"] for item in rows)
    assert all(item["maturity"] != "live_verified" for item in rows)
    for item in rows:
        for word in FORBIDDEN:
            assert word not in item["state"]
            assert f" {word} " not in f" {item['explanation']} "
        assert "<" not in item["explanation"]
        assert "payload" not in item
    entry = client.get("/api/v1/analysis/results?category=internet_exposure_candidate&state=supported_candidate", headers=headers)
    assert entry.status_code == 200
    assert any("customer-ordering" in item["service_key"] for item in entry.json())
    one = client.get(f"/api/v1/analysis/results/{rows[0]['id']}", headers=headers)
    assert one.status_code == 200
    assert client.get(f"/api/v1/analysis/results/{rows[0]['id']}", headers=other).status_code == 404
    assert client.get(f"/api/v1/analysis/results/{uuid.uuid4()}", headers=headers).json()["detail"] == "Analysis object not found"
    gaps = client.get("/api/v1/analysis/gaps", headers=headers)
    assert gaps.status_code == 200
    assert any(item["state"] in {"unknown", "conflicting", "unsupported"} for item in gaps.json())
    rules = client.get("/api/v1/analysis/rules", headers=headers)
    assert rules.status_code == 200
    assert rules.json()["bounds"]["max_depth"] == 4
    assert "internet-entry-candidate-v1" in {item["rule_id"] for item in rules.json()["rules"]}
    current = client.get("/api/v1/analysis/current", headers=headers)
    assert current.json()["id"] == body["id"]
    with Session(get_engine()) as db:
        _tenant_id, workspace_id = _ids(headers)
        node_count = db.scalar(select(func.count()).select_from(GraphNode).where(GraphNode.workspace_id == workspace_id))
        result_count = db.scalar(select(func.count()).select_from(AnalysisResult).where(AnalysisResult.workspace_id == workspace_id))
    assert node_count
    assert result_count == body["result_count"]


def test_failed_run_preserves_the_current_analysis(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _workspace()
    snapshot_id = _snapshot(headers)
    created = client.post("/api/v1/analysis/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "keep-current-01"})
    assert created.status_code == 201, created.text
    current_id = created.json()["id"]
    tenant_id, workspace_id = _ids(headers)
    with Session(get_engine()) as db:
        with pytest.raises(GraphFailure) as exc:
            execute(
                db,
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                snapshot_id=uuid.UUID(snapshot_id),
                actor=headers["X-Actor"],
                idempotency_key="cancelled-run-01",
                cancelled=lambda: True,
            )
        assert exc.value.code == "cancelled"
    monkeypatch.setenv("THREATSIGHT_KILL_SWITCH", "true")
    get_settings.cache_clear()
    try:
        blocked = client.post("/api/v1/analysis/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "killed-run-0001"})
        assert blocked.status_code == 503
    finally:
        monkeypatch.delenv("THREATSIGHT_KILL_SWITCH", raising=False)
        get_settings.cache_clear()
    current = client.get("/api/v1/analysis/current", headers=headers)
    assert current.json()["id"] == current_id
    assert current.json()["is_current"] is True
    with Session(get_engine()) as db:
        cancelled = db.scalar(select(AnalysisRun).where(AnalysisRun.workspace_id == workspace_id, AnalysisRun.status == "cancelled"))
        assert cancelled is not None
        assert cancelled.is_current is False
        failed = db.scalar(select(AnalysisRun).where(AnalysisRun.workspace_id == workspace_id, AnalysisRun.failure_code == "kill_switch"))
        assert failed is not None
        assert failed.is_current is False


def test_cancelled_snapshot_is_rejected(client: TestClient) -> None:
    headers = _workspace()
    tenant_id, workspace_id = _ids(headers)
    with Session(get_engine()) as db:
        with pytest.raises(GraphFailure):
            materialize(
                db,
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                actor=headers["X-Actor"],
                idempotency_key="cancelled-graph-1",
                fixture="nordic-retail",
                cancelled=lambda: True,
            )
        rejected = db.scalar(select(GraphSnapshot).where(GraphSnapshot.workspace_id == workspace_id, GraphSnapshot.status == "cancelled"))
        assert rejected is not None
        snapshot_id = str(rejected.id)
    response = client.post("/api/v1/analysis/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "reject-cancelled"})
    assert response.status_code == 404
    assert response.json()["detail"] == "Analysis object not found"
