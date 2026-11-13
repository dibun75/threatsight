from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.connectors.microsoft.fixtures import TENANT, azure_configuration
from threatsight_api.main import app
from threatsight_api.persistence.models import Workspace, WorkspaceMembership
from threatsight_api.persistence.session import get_engine

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(subject: str) -> dict[str, str]:
    key = f"ms-{uuid.uuid4().hex[:10]}"
    with Session(get_engine()) as db:
        tenant_id = db.scalar(select(Workspace.tenant_id).where(Workspace.key == "default"))
        workspace = Workspace(tenant_id=tenant_id, key=key, name=key, status="active")
        db.add(workspace)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, role="workspace-admin"))
        db.commit()
    return {"X-Actor": subject, "X-Workspace-Key": key}


def test_microsoft_connector_api_rejects_client_control_and_redacts_locators(client: TestClient) -> None:
    headers = _workspace(f"ms-{uuid.uuid4().hex[:8]}")
    other = _workspace(f"ms-{uuid.uuid4().hex[:8]}")
    marker = "marker-query-value"
    runner = client.post("/api/v1/connectors/runners", headers=headers, json={"name": f"runner-{uuid.uuid4().hex[:6]}", "capabilities": ["inventory"]})
    assert runner.status_code == 201, runner.text
    secret = client.post("/api/v1/connectors/secret-references", headers=headers, json={
        "name": f"locator-{uuid.uuid4().hex[:6]}", "provider": "customer_runner", "locator": "synthetic-locator",
    })
    assert secret.status_code == 201, secret.text
    assert secret.json()["locator"] == "[REDACTED]"
    rejected = client.post("/api/v1/connectors/instances", headers=headers, json={
        "connector_key": "azure.resource_graph", "name": f"azure-{uuid.uuid4().hex[:6]}",
        "runner_id": runner.json()["id"], "mode": "fixture", "maturity": "live_verified",
        "configuration": {**azure_configuration(), "query": marker},
    })
    assert rejected.status_code == 422
    assert marker not in rejected.text
    created = client.post("/api/v1/connectors/instances", headers=headers, json={
        "connector_key": "azure.resource_graph", "name": f"azure-{uuid.uuid4().hex[:6]}",
        "runner_id": runner.json()["id"], "secret_reference_id": secret.json()["id"],
        "mode": "fixture", "maturity": "unsupported", "configuration": azure_configuration(),
    })
    assert created.status_code == 201, created.text
    assert created.json()["maturity"] == "fixture_tested"
    assert created.json()["configuration"]["microsoft_tenant_id"] == TENANT
    assert "synthetic-locator" not in created.text
    blocked = client.post("/api/v1/connectors/jobs", headers=headers, json={
        "connector_instance_id": created.json()["id"], "job_type": "inventory",
        "idempotency_key": uuid.uuid4().hex, "input": {"query": marker},
    })
    assert blocked.status_code == 422
    assert marker not in blocked.text
    queued = client.post("/api/v1/connectors/jobs", headers=headers, json={
        "connector_instance_id": created.json()["id"], "job_type": "inventory",
        "idempotency_key": uuid.uuid4().hex, "input": {},
    })
    assert queued.status_code == 201, queued.text
    listed = client.get("/api/v1/connectors/jobs", headers=headers)
    assert "synthetic-locator" not in listed.text
    foreign = client.get("/api/v1/connectors/instances", headers=other)
    assert foreign.status_code == 200
    assert created.json()["id"] not in {item["id"] for item in foreign.json()}
    client.post(f"/api/v1/connectors/runners/{runner.json()['id']}/revoke", headers=headers)
    claim = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {runner.json()['credential']}"})
    assert claim.status_code == 401
