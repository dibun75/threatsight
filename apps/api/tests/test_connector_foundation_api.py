from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.config import get_settings
from threatsight_api.main import app
from threatsight_api.persistence.models import ConnectorJob, Tenant, Workspace, WorkspaceMembership
from threatsight_api.persistence.session import get_engine

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _isolated(subject: str, role: str = "workspace-admin") -> dict[str, str]:
    key = f"ws-{uuid.uuid4().hex[:10]}"
    with Session(get_engine()) as db:
        tenant_id = db.scalar(select(Workspace.tenant_id).where(Workspace.key == "default"))
        workspace = Workspace(tenant_id=tenant_id, key=key, name=key, status="active")
        db.add(workspace)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, role=role))
        db.commit()
    return {"X-Actor": subject, "X-Workspace-Key": key}


def test_rbac_isolation_redaction_runner_rotation_and_job_lifecycle(client: TestClient) -> None:
    suffix = uuid.uuid4().hex[:8]
    admin = f"connector-admin-{suffix}"
    auditor = f"connector-auditor-{suffix}"
    headers = _isolated(admin)
    with Session(get_engine()) as db:
        workspace = db.scalar(select(Workspace).where(Workspace.key == headers["X-Workspace-Key"]))
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=auditor, role="auditor"))
        db.commit()

    denied = client.post(
        "/api/v1/connectors/secret-references",
        headers={"X-Actor": auditor, "X-Role": "platform-admin"},
        json={"name": "denied", "provider": "customer_runner", "locator": "local://denied"},
    )
    assert denied.status_code == 403

    secret_value = f"local://vault/{suffix}?token=must-not-leak"
    secret = client.post(
        "/api/v1/connectors/secret-references", headers=headers,
        json={"name": f"fixture-{suffix}", "provider": "customer_runner", "locator": secret_value},
    )
    assert secret.status_code == 201, secret.text
    assert secret.json()["locator"] == "[REDACTED]"
    assert secret_value not in secret.text

    runner = client.post(
        "/api/v1/connectors/runners", headers=headers,
        json={"name": f"runner-{suffix}", "capabilities": ["inventory"]},
    )
    assert runner.status_code == 201, runner.text
    credential = runner.json()["credential"]
    runner_id = runner.json()["id"]
    assert credential.startswith("tsr_")
    assert credential not in client.get("/api/v1/connectors/runners", headers=headers).text

    connector = client.post(
        "/api/v1/connectors/instances", headers=headers,
        json={
            "connector_key": "fixture", "name": f"fixture-{suffix}",
            "runner_id": runner_id, "secret_reference_id": secret.json()["id"],
            "mode": "fixture", "maturity": "fixture_tested",
            "configuration": {"token": "inline-must-not-store", "scope": "bounded"},
        },
    )
    assert connector.status_code == 422
    assert "inline-must-not-store" not in connector.text
    connector = client.post(
        "/api/v1/connectors/instances", headers=headers,
        json={
            "connector_key": "fixture", "name": f"fixture-{suffix}",
            "runner_id": runner_id, "secret_reference_id": secret.json()["id"],
            "mode": "fixture", "maturity": "fixture_tested",
            "configuration": {"scope": "bounded"},
        },
    )
    assert connector.status_code == 201, connector.text

    job = client.post(
        "/api/v1/connectors/jobs", headers=headers,
        json={
            "connector_instance_id": connector.json()["id"], "job_type": "inventory",
            "idempotency_key": f"job-{suffix}", "input": {"password": "redact-me"},
        },
    )
    assert job.status_code == 422
    assert "redact-me" not in job.text
    job = client.post(
        "/api/v1/connectors/jobs", headers=headers,
        json={
            "connector_instance_id": connector.json()["id"], "job_type": "inventory",
            "idempotency_key": f"job-{suffix}", "input": {"scope": "bounded"},
        },
    )
    assert job.status_code == 201, job.text
    duplicate = client.post(
        "/api/v1/connectors/jobs", headers=headers,
        json={
            "connector_instance_id": connector.json()["id"], "job_type": "inventory",
            "idempotency_key": f"job-{suffix}", "input": {},
        },
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["id"] == job.json()["id"]

    claimed = client.post(
        "/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {credential}"}
    )
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["id"] == job.json()["id"]
    cancelled = client.post(f"/api/v1/connectors/jobs/{job.json()['id']}/cancel", headers=headers)
    assert cancelled.status_code == 200
    progress = client.post(
        f"/api/v1/runner/v1/jobs/{job.json()['id']}/progress",
        headers={"Authorization": f"Bearer {credential}"},
        json={"progress": {"records": 1}},
    )
    assert progress.status_code == 409

    rotated = client.post(f"/api/v1/connectors/runners/{runner_id}/rotate", headers=headers)
    assert rotated.status_code == 200
    assert client.post(
        "/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {credential}"}
    ).status_code == 401

    other_key = f"connector-other-{suffix}"
    with Session(get_engine()) as db:
        default = db.scalar(select(Workspace).where(Workspace.key == "default"))
        other = Workspace(tenant_id=default.tenant_id, key=other_key, name="Other", status="active")
        db.add(other)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=other.id, subject=admin, role="workspace-admin"))
        db.commit()
    isolated = client.get(
        "/api/v1/connectors/secret-references",
        headers={**headers, "X-Workspace-Key": other_key},
    )
    assert isolated.status_code == 200
    assert isolated.json() == []


def _runner(client: TestClient, headers: dict[str, str], suffix: str) -> tuple[str, str]:
    created = client.post(
        "/api/v1/connectors/runners", headers=headers,
        json={"name": f"runner-{suffix}", "capabilities": ["inventory"]},
    )
    assert created.status_code == 201, created.text
    return created.json()["id"], created.json()["credential"]


def _connector(client: TestClient, headers: dict[str, str], runner_id: str, suffix: str) -> str:
    created = client.post(
        "/api/v1/connectors/instances", headers=headers,
        json={
            "connector_key": "fixture", "name": f"fixture-{suffix}", "runner_id": runner_id,
            "mode": "fixture", "maturity": "fixture_tested", "configuration": {"scope": "bounded"},
        },
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _enqueue(client: TestClient, headers: dict[str, str], connector_id: str, suffix: str, **extra) -> dict:
    body = {
        "connector_instance_id": connector_id,
        "job_type": "inventory",
        "idempotency_key": f"job-{suffix}",
        "input": {"scope": "bounded"},
    }
    body.update(extra)
    created = client.post("/api/v1/connectors/jobs", headers=headers, json=body)
    assert created.status_code == 201, created.text
    return created.json()


def test_secret_shaped_and_oversized_input_is_rejected(client: TestClient) -> None:
    suffix = uuid.uuid4().hex[:8]
    admin = f"connector-bound-{suffix}"
    headers = _isolated(admin)
    runner_id, _credential = _runner(client, headers, suffix)
    rejected = client.post(
        "/api/v1/connectors/instances", headers=headers,
        json={
            "connector_key": "fixture", "name": f"secret-{suffix}", "runner_id": runner_id,
            "configuration": {"api_key": "must-not-store"},
        },
    )
    assert rejected.status_code == 422
    assert "must-not-store" not in rejected.text
    connector_id = _connector(client, headers, runner_id, suffix)
    oversized = client.post(
        "/api/v1/connectors/jobs", headers=headers,
        json={
            "connector_instance_id": connector_id, "job_type": "inventory",
            "idempotency_key": f"big-{suffix}", "input": {"scope": "x" * 70_000},
        },
    )
    assert oversized.status_code == 422
    assert "x" * 70_000 not in oversized.text


def test_runner_cannot_claim_or_replay_across_credentials(client: TestClient) -> None:
    suffix = uuid.uuid4().hex[:8]
    admin = f"connector-claim-{suffix}"
    headers = _isolated(admin)
    runner_a, credential_a = _runner(client, headers, f"a-{suffix}")
    _runner_b, credential_b = _runner(client, headers, f"b-{suffix}")
    job = _enqueue(client, headers, _connector(client, headers, runner_a, suffix), suffix)
    foreign = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {credential_b}"})
    assert foreign.status_code == 200
    assert foreign.json() is None
    owned = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {credential_a}"})
    assert owned.status_code == 200
    assert owned.json()["id"] == job["id"]
    with Session(get_engine()) as db:
        record = db.get(ConnectorJob, uuid.UUID(job["id"]))
        record.lease_expires_at = datetime.now(UTC) - timedelta(seconds=5)
        db.commit()
    expired = client.post(
        f"/api/v1/runner/v1/jobs/{job['id']}/progress",
        headers={"Authorization": f"Bearer {credential_a}"},
        json={"progress": {"records": 1}},
    )
    assert expired.status_code == 409
    reclaimed = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {credential_a}"})
    assert reclaimed.status_code == 200
    assert reclaimed.json()["id"] == job["id"]
    assert reclaimed.json()["attempt_count"] == 2
    stolen = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {credential_b}"})
    assert stolen.json() is None


def test_retry_exhaustion_dead_letters_and_cancellation_wins(client: TestClient) -> None:
    suffix = uuid.uuid4().hex[:8]
    admin = f"connector-retry-{suffix}"
    headers = _isolated(admin)
    runner_id, credential = _runner(client, headers, suffix)
    job = _enqueue(
        client, headers, _connector(client, headers, runner_id, suffix), suffix, max_attempts=2,
    )
    auth = {"Authorization": f"Bearer {credential}"}
    claimed = client.post("/api/v1/runner/v1/claim", headers=auth)
    assert claimed.json()["id"] == job["id"]
    failed = client.post(
        f"/api/v1/runner/v1/jobs/{job['id']}/fail", headers=auth,
        json={"code": "temporary", "detail": "try again", "retryable": True},
    )
    assert failed.status_code == 200
    assert failed.json()["status"] == "retry_wait"
    with Session(get_engine()) as db:
        record = db.get(ConnectorJob, uuid.UUID(job["id"]))
        record.available_at = datetime.now(UTC)
        db.commit()
    second = client.post("/api/v1/runner/v1/claim", headers=auth)
    assert second.json()["attempt_count"] == 2
    dead = client.post(
        f"/api/v1/runner/v1/jobs/{job['id']}/fail", headers=auth,
        json={"code": "temporary", "detail": "still failing", "retryable": True},
    )
    assert dead.json()["status"] == "dead_letter"
    replay = client.post("/api/v1/runner/v1/claim", headers=auth)
    assert replay.json() is None

    other = _enqueue(
        client, headers, _connector(client, headers, runner_id, f"cancel-{suffix}"), f"cancel-{suffix}",
    )
    cancel_claim = client.post("/api/v1/runner/v1/claim", headers=auth)
    assert cancel_claim.json()["id"] == other["id"]
    cancelled = client.post(f"/api/v1/connectors/jobs/{other['id']}/cancel", headers=headers)
    assert cancelled.json()["status"] == "leased"
    with Session(get_engine()) as db:
        record = db.get(ConnectorJob, uuid.UUID(other["id"]))
        record.lease_expires_at = datetime.now(UTC) - timedelta(seconds=5)
        db.commit()
    released = client.post("/api/v1/runner/v1/claim", headers=auth)
    assert released.json() is None
    with Session(get_engine()) as db:
        assert db.get(ConnectorJob, uuid.UUID(other["id"])).status == "cancelled"


def test_kill_switch_blocks_enqueue_and_claim(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    suffix = uuid.uuid4().hex[:8]
    admin = f"connector-kill-{suffix}"
    headers = _isolated(admin)
    _runner_id, credential = _runner(client, headers, suffix)
    connector_id = _connector(client, headers, _runner_id, suffix)
    monkeypatch.setenv("THREATSIGHT_KILL_SWITCH", "true")
    get_settings.cache_clear()
    try:
        blocked = client.post(
            "/api/v1/connectors/jobs", headers=headers,
            json={
                "connector_instance_id": connector_id, "job_type": "inventory",
                "idempotency_key": f"stopped-{suffix}", "input": {},
            },
        )
        assert blocked.status_code == 503
        claim = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {credential}"})
        assert claim.status_code == 503
    finally:
        monkeypatch.delenv("THREATSIGHT_KILL_SWITCH", raising=False)
        get_settings.cache_clear()


def test_runner_claim_cannot_cross_tenants(client: TestClient) -> None:
    suffix = uuid.uuid4().hex[:8]
    admin = f"connector-tenant-{suffix}"
    headers = _isolated(admin)
    runner_id, credential = _runner(client, headers, suffix)
    job = _enqueue(client, headers, _connector(client, headers, runner_id, suffix), suffix)
    other_key = f"tenant-ws-{suffix}"
    with Session(get_engine()) as db:
        tenant = Tenant(key=f"tenant-{suffix}", name="Other tenant", status="active")
        db.add(tenant)
        db.flush()
        other = Workspace(tenant_id=tenant.id, key=other_key, name="Other tenant workspace", status="active")
        db.add(other)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=other.id, subject=admin, role="workspace-admin"))
        db.commit()
    other_headers = {"X-Actor": admin, "X-Workspace-Key": other_key}
    _other_runner, other_credential = _runner(client, other_headers, f"other-{suffix}")
    foreign = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {other_credential}"})
    assert foreign.status_code == 200
    assert foreign.json() is None
    owned = client.post("/api/v1/runner/v1/claim", headers={"Authorization": f"Bearer {credential}"})
    assert owned.status_code == 200
    assert owned.json()["id"] == job["id"]
