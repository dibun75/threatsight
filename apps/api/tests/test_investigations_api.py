from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.graph.materialize import materialize
from threatsight_api.main import app
from threatsight_api.persistence.models import Workspace, WorkspaceMembership
from threatsight_api.persistence.session import get_engine

pytestmark = pytest.mark.skipif(os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() not in {"1", "true", "yes"}, reason="requires postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(role: str = "workspace-admin") -> dict[str, str]:
    subject = f"inv-{uuid.uuid4().hex[:8]}"
    key = f"inv-{uuid.uuid4().hex[:10]}"
    with Session(get_engine()) as db:
        tenant_id = db.scalar(select(Workspace.tenant_id).where(Workspace.key == "default"))
        workspace = Workspace(tenant_id=tenant_id, key=key, name=key, status="active")
        db.add(workspace)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, role=role))
        db.commit()
        return {"X-Actor": subject, "X-Workspace-Key": key, "tenant": str(tenant_id), "id": str(workspace.id)}


def test_investigation_is_scoped_and_does_not_invent_actions(client: TestClient) -> None:
    headers = _workspace()
    other = _workspace()
    viewer_subject = f"view-{uuid.uuid4().hex[:8]}"
    with Session(get_engine()) as db:
        db.add(WorkspaceMembership(workspace_id=uuid.UUID(headers["id"]), subject=viewer_subject, role="viewer"))
        db.commit()
    viewer = {"X-Actor": viewer_subject, "X-Workspace-Key": headers["X-Workspace-Key"]}
    with Session(get_engine()) as db:
        materialize(
            db,
            tenant_id=uuid.UUID(headers["tenant"]),
            workspace_id=uuid.UUID(headers["id"]),
            actor=headers["X-Actor"],
            idempotency_key=f"inv-{uuid.uuid4().hex[:8]}",
            fixture="correlation",
        )
    listed = client.get("/api/v1/decisions/services", headers=headers)
    service_id = listed.json()["services"][0]["service_id"]
    response = client.get(f"/api/v1/investigations/services/{service_id}", headers=headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["owner_state"] == "not_assigned"
    assert body["deadline_state"] == "not_recorded"
    assert body["comparison"] == "Comparison unavailable."
    assert body["score"] is None
    assert body["actions"] == []
    assert body["assets"]
    assert body["data_context"] == "Synthetic enterprise evidence"
    assert "compromise" not in body["explanation"].lower()
    foreign = client.get(f"/api/v1/investigations/services/{service_id}", headers=other)
    missing = client.get(f"/api/v1/investigations/services/{uuid.uuid4()}", headers=headers)
    assert foreign.status_code == missing.status_code == 404
    viewed = client.get(f"/api/v1/investigations/services/{service_id}", headers=viewer)
    assert viewed.status_code == 200
    denied = client.get(f"/api/v1/investigations/paths/{uuid.uuid4()}", headers=headers)
    assert denied.status_code == 404
