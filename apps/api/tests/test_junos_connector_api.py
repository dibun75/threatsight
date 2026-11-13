from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.connectors.junos.fixtures import DEVICE, PIN, configuration
from threatsight_api.main import app
from threatsight_api.persistence.models import AuditEvent, ConnectorJobAudit
from threatsight_api.persistence.session import get_engine

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(subject: str) -> dict[str, str]:
    key = f"jn-{uuid.uuid4().hex[:10]}"
    with Session(get_engine()) as db:
        from threatsight_api.persistence.models import Workspace, WorkspaceMembership

        tenant_id = db.scalar(select(Workspace.tenant_id).where(Workspace.key == "default"))
        workspace = Workspace(tenant_id=tenant_id, key=key, name=key, status="active")
        db.add(workspace)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, role="workspace-admin"))
        db.commit()
    return {"X-Actor": subject, "X-Workspace-Key": key}


def _live_configuration() -> dict:
    return {
        "device_id": DEVICE,
        "target_host": "10.8.0.1",
        "host_key_fingerprint": PIN,
        "host_key_algorithm": "ssh-ed25519",
    }


def test_junos_api_rejects_foreign_scope_revoked_runners_and_client_rpc(client: TestClient) -> None:
    headers = _workspace(f"jn-{uuid.uuid4().hex[:8]}")
    other = _workspace(f"jn-{uuid.uuid4().hex[:8]}")
    runner = client.post("/api/v1/connectors/runners", headers=headers, json={"name": f"runner-{uuid.uuid4().hex[:6]}", "capabilities": ["inventory"]})
    assert runner.status_code == 201, runner.text
    secret = client.post("/api/v1/connectors/secret-references", headers=headers, json={
        "name": f"locator-{uuid.uuid4().hex[:6]}", "provider": "customer_runner", "locator": "synthetic-locator",
    })
    assert secret.status_code == 201, secret.text
    assert secret.json()["locator"] == "[REDACTED]"
    rejected = client.post("/api/v1/connectors/instances", headers=headers, json={
        "connector_key": "junos.device", "name": f"junos-{uuid.uuid4().hex[:6]}",
        "runner_id": runner.json()["id"], "mode": "fixture", "maturity": "live_verified",
        "configuration": {**configuration(), "target_host": "evil.example"},
    })
    assert rejected.status_code == 422
    assert "evil.example" not in rejected.text
    created = client.post("/api/v1/connectors/instances", headers=headers, json={
        "connector_key": "junos.device", "name": f"junos-{uuid.uuid4().hex[:6]}",
        "runner_id": runner.json()["id"], "secret_reference_id": secret.json()["id"],
        "mode": "fixture", "maturity": "unsupported", "configuration": configuration(),
    })
    assert created.status_code == 201, created.text
    assert created.json()["maturity"] == "fixture_tested"
    assert "synthetic-locator" not in created.text
    foreign_secret = client.post("/api/v1/connectors/instances", headers=other, json={
        "connector_key": "junos.device", "name": f"junos-{uuid.uuid4().hex[:6]}",
        "runner_id": runner.json()["id"], "secret_reference_id": secret.json()["id"],
        "mode": "live", "maturity": "experimental", "configuration": _live_configuration(),
    })
    assert foreign_secret.status_code in {404, 422}
    blocked = client.post("/api/v1/connectors/jobs", headers=headers, json={
        "connector_instance_id": created.json()["id"], "job_type": "inventory",
        "idempotency_key": uuid.uuid4().hex, "input": {"rpc": "<edit-config>secret-shaped-value</edit-config>"},
    })
    assert blocked.status_code == 422
    assert "secret-shaped-value" not in blocked.text
    assert "<edit-config>" not in blocked.text
    with Session(get_engine()) as db:
        audit = db.scalar(select(AuditEvent).where(
            AuditEvent.entity_id == uuid.UUID(created.json()["id"]),
            AuditEvent.action == "rpc_rejected",
        ))
    assert audit is not None
    assert audit.payload == {"rejected": True}
    foreign = client.get("/api/v1/connectors/instances", headers=other)
    assert created.json()["id"] not in {item["id"] for item in foreign.json()}
    foreign_secrets = client.get("/api/v1/connectors/secret-references", headers=other)
    assert secret.json()["id"] not in {item["id"] for item in foreign_secrets.json()}
    queued = client.post("/api/v1/connectors/jobs", headers=headers, json={
        "connector_instance_id": created.json()["id"], "job_type": "inventory",
        "idempotency_key": uuid.uuid4().hex, "input": {},
    })
    assert queued.status_code == 201, queued.text
    claim = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {runner.json()['credential']}"})
    assert claim.status_code == 200, claim.text
    assert claim.json()["dispatch"]["secret_locator"] == "synthetic-locator"
    failed = client.post(
        f"/api/v1/runner/v1/jobs/{queued.json()['id']}/fail",
        headers={"Authorization": f"Bearer {runner.json()['credential']}"},
        json={"code": "rpc_rejected", "detail": "<rpc-reply>secret-shaped-value</rpc-reply>", "retryable": False},
    )
    assert failed.status_code == 200, failed.text
    assert "secret-shaped-value" not in failed.text
    assert "<rpc-reply>" not in failed.text
    with Session(get_engine()) as db:
        row = db.scalar(select(ConnectorJobAudit).where(ConnectorJobAudit.job_id == uuid.UUID(queued.json()["id"])))
    assert row is not None
    assert "secret-shaped-value" not in str(row.payload)
    assert "<rpc-reply>" not in str(row.payload)
    client.post(f"/api/v1/connectors/runners/{runner.json()['id']}/revoke", headers=headers)
    revoked = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {runner.json()['credential']}"})
    assert revoked.status_code == 401
