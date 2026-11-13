from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from threatsight_api.graph.materialize import materialize
from threatsight_api.investigations.reference import install
from threatsight_api.main import app
from threatsight_api.persistence.models import EvidenceRecord, Workspace, WorkspaceMembership
from threatsight_api.persistence.session import get_engine

pytestmark = pytest.mark.skipif(os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() not in {"1", "true", "yes"}, reason="requires postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace() -> dict[str, str]:
    subject = f"ref-{uuid.uuid4().hex[:8]}"
    key = f"ref-{uuid.uuid4().hex[:10]}"
    with Session(get_engine()) as db:
        tenant_id = db.scalar(text("SELECT tenant_id FROM workspaces WHERE key = 'default'"))
        workspace = Workspace(tenant_id=tenant_id, key=key, name=key, status="active")
        db.add(workspace)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, role="workspace-admin"))
        db.commit()
        return {"X-Actor": subject, "X-Workspace-Key": key, "tenant": str(tenant_id), "id": str(workspace.id)}


def test_reference_loader_is_idempotent_and_evidence_stays_on_its_service(client: TestClient) -> None:
    headers = _workspace()
    other = _workspace()
    with Session(get_engine()) as db:
        materialize(
            db,
            tenant_id=uuid.UUID(headers["tenant"]),
            workspace_id=uuid.UUID(headers["id"]),
            actor=headers["X-Actor"],
            idempotency_key=f"ref-{uuid.uuid4().hex[:8]}",
            fixture="correlation",
        )
        db.commit()
    with Session(get_engine()) as db:
        install(db.connection())
        install(db.connection())
        db.add(EvidenceRecord(title="AI product page", evidence_type="document", owner="Unassigned", status="accepted", source_reference="ai-product-page"))
        db.execute(
            text(
                """
                INSERT INTO graph_nodes (
                    id, tenant_id, workspace_id, snapshot_id, node_type, source_key, vendor_id, label,
                    maturity, evidence_mode, connector_key, source_contract, source_record_id,
                    collected_at, materialized_at, freshness, confidence, limitations, lifecycle, attributes
                )
                SELECT :id, tenant_id, workspace_id, snapshot_id, 'business_service', :source_key, 'synthetic', 'Customer ordering',
                       'synthetic', 'configured', 'synthetic-fixture', 'synthetic-service.v1', :source_key,
                       now(), now(), 'fresh', 'stated', '[]'::jsonb, 'active', '{}'::jsonb
                FROM graph_nodes
                WHERE workspace_id = :workspace AND source_key = 'synthetic.fixture:service:customer-ordering'
                LIMIT 1
                """
            ),
            {"id": str(uuid.uuid4()), "source_key": "synthetic.fixture:service:name-collision", "workspace": headers["id"]},
        )
        db.commit()
        counts = db.execute(text("SELECT evidence_key, count(*) FROM reference_evidence_links WHERE workspace_id = :workspace GROUP BY 1"), {"workspace": headers["id"]}).all()
    assert counts
    assert all(row[1] == 1 for row in counts)
    listed = client.get("/api/v1/decisions/services", headers=headers)
    assert listed.status_code == 200
    services = {item["name"]: item for item in listed.json()["services"]}
    assert services["Privileged administration"]["control_gap"] == "Configured, not observed."
    assert services["Remote access"]["control_gap"] == "Configured, not observed."
    assert "No control record" not in services["Remote access"]["explanation"]
    assert ":software" not in services["Remote access"]["explanation"]
    ordering = next(item for item in listed.json()["services"] if item["name"] == "Customer ordering")
    filtered = client.get(f"/api/v1/evidence?service={ordering['service_id']}", headers=headers)
    assert filtered.status_code == 200
    assert filtered.headers["x-total-count"] == "1"
    titles = [item["title"] for item in filtered.json()]
    assert titles == ["Installed version is not observed"]
    assert "AI product page" not in titles
    page = client.get(f"/api/v1/evidence?service={ordering['service_id']}&limit=1&offset=1", headers=headers)
    assert page.status_code == 200
    assert page.json() == []
    assert page.headers["x-total-count"] == "1"
    with Session(get_engine()) as db:
        collision_id = db.scalar(text("SELECT id FROM graph_nodes WHERE workspace_id = :workspace AND source_key = 'synthetic.fixture:service:name-collision'"), {"workspace": headers["id"]})
    same_name = client.get(f"/api/v1/evidence?service={collision_id}", headers=headers)
    assert same_name.status_code == 200
    assert same_name.json() == []
    assert same_name.headers["x-total-count"] == "0"
    missing = client.get(f"/api/v1/evidence?service={uuid.uuid4()}", headers=headers)
    foreign = client.get(f"/api/v1/evidence?service={ordering['service_id']}", headers=other)
    forged = client.get(f"/api/v1/evidence?service={uuid.uuid4()}", headers=headers)
    assert missing.status_code == foreign.status_code == forged.status_code == 404
