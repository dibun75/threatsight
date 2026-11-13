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


def _workspace() -> dict[str, str]:
    subject = f"dec-{uuid.uuid4().hex[:8]}"
    key = f"dec-{uuid.uuid4().hex[:10]}"
    with Session(get_engine()) as db:
        tenant_id = db.scalar(select(Workspace.tenant_id).where(Workspace.key == "default"))
        workspace = Workspace(tenant_id=tenant_id, key=key, name=key, status="active")
        db.add(workspace)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, role="workspace-admin"))
        db.commit()
        return {"X-Actor": subject, "X-Workspace-Key": key, "tenant": str(tenant_id), "id": str(workspace.id)}


def test_decisions_use_memberships_and_hide_foreign_services(client: TestClient) -> None:
    headers = _workspace()
    other = _workspace()
    with Session(get_engine()) as db:
        materialize(
            db,
            tenant_id=uuid.UUID(headers["tenant"]),
            workspace_id=uuid.UUID(headers["id"]),
            actor=headers["X-Actor"],
            idempotency_key=f"dec-{uuid.uuid4().hex[:8]}",
            fixture="correlation",
        )
    listed = client.get("/api/v1/decisions/services", headers=headers)
    assert listed.status_code == 200
    body = listed.json()
    names = [item["name"] for item in body["services"]]
    assert names == ["Customer ordering", "Privileged administration", "Remote access"]
    assets = {item["name"]: item["members"][0]["source_key"] for item in body["services"]}
    assert len(set(assets.values())) == 3
    assert body["outcomes"]["live_relevant_advisories"] == 0
    assert all(item["state"] == "no_current_relevant_match" for item in body["services"])
    service_id = body["services"][0]["service_id"]
    assert client.get(f"/api/v1/decisions/services/{service_id}", headers=headers).status_code == 200
    foreign = client.get(f"/api/v1/decisions/services/{service_id}", headers=other)
    missing = client.get(f"/api/v1/decisions/services/{uuid.uuid4()}", headers=headers)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json()["detail"] == missing.json()["detail"] == "Decision not found"
