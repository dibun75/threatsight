from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatsight_api.config import get_settings
from threatsight_api.connectors.sdk import CollectionEnvelope, NormalizedRecord
from threatsight_api.graph.materialize import materialize
from threatsight_api.graph.sanitize import GraphFailure
from threatsight_api.main import app
from threatsight_api.persistence.models import (
    AuditEvent,
    BusinessService,
    ConnectorInstance,
    ConnectorJob,
    ConnectorJobAttempt,
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    Workspace,
    WorkspaceMembership,
)
from threatsight_api.persistence.session import get_engine

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires postgres")
FORBIDDEN = ("exploitable", "compromised", "internet_exposed", "control_effective", "reachable", "vulnerable")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(subject: str, role: str = "workspace-admin") -> dict[str, str]:
    key = f"gr-{uuid.uuid4().hex[:10]}"
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


def test_graph_api_isolates_tenants_and_publishes_only_completed_snapshots(client: TestClient) -> None:
    headers = _workspace(f"gr-{uuid.uuid4().hex[:8]}")
    other = _workspace(f"gr-{uuid.uuid4().hex[:8]}")
    operator = _workspace(f"gr-{uuid.uuid4().hex[:8]}", role="operator")
    with Session(get_engine()) as db:
        before = db.scalar(select(func.count()).select_from(BusinessService))
    denied = client.post("/api/v1/graph/builds", headers=operator, json={"idempotency_key": "operator-build-1", "fixture": "nordic-retail"})
    assert denied.status_code == 403
    created = client.post("/api/v1/graph/builds", headers=headers, json={"idempotency_key": "nordic-build-1", "fixture": "nordic-retail"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["is_current"] is True
    assert body["status"] == "completed"
    assert "not_an_exposure_finding" in body["limitations"]
    again = client.post("/api/v1/graph/builds", headers=headers, json={"idempotency_key": "nordic-build-1", "fixture": "nordic-retail"})
    assert again.status_code == 201, again.text
    assert again.json()["id"] == body["id"]
    second = client.post("/api/v1/graph/builds", headers=headers, json={"idempotency_key": "nordic-build-2", "fixture": "nordic-retail"})
    assert second.json()["content_hash"] == body["content_hash"]
    assert second.json()["id"] != body["id"]
    assert second.json()["is_current"] is True
    listed = client.get("/api/v1/graph/snapshots", headers=headers)
    assert listed.status_code == 200
    assert sum(bool(item["is_current"]) for item in listed.json()) == 1
    assert all(item["status"] == "completed" for item in listed.json())
    foreign = client.get(f"/api/v1/graph/snapshots/{body['id']}", headers=other)
    missing = client.get(f"/api/v1/graph/snapshots/{uuid.uuid4()}", headers=headers)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json() == {"detail": "Graph object not found"}
    nodes = client.get("/api/v1/graph/nodes?limit=100", headers=headers)
    assert nodes.status_code == 200, nodes.text
    assert nodes.json() == sorted(nodes.json(), key=lambda item: (item["node_type"], item["source_key"]))
    blob = nodes.text.lower() + client.get("/api/v1/graph/edges?limit=100", headers=headers).text.lower()
    for word in FORBIDDEN:
        assert word not in blob
    assert client.get("/api/v1/graph/nodes?node_type=RELATED_TO", headers=headers).status_code == 422
    assert client.get("/api/v1/graph/edges?edge_type=RELATED_TO", headers=headers).status_code == 422
    assert client.get("/api/v1/graph/nodes?limit=101", headers=headers).status_code == 422
    services = client.get("/api/v1/graph/services", headers=headers)
    assert len(services.json()) == 3
    assert {item["maturity"] for item in services.json()} == {"synthetic"}
    ordering = next(item for item in services.json() if item["label"] == "Customer ordering")
    members = client.get(f"/api/v1/graph/services/{ordering['id']}/members", headers=headers)
    assert members.status_code == 200, members.text
    assert members.json()["members"]
    assert all(item["evidence_mode"] == "manual" for item in members.json()["members"])
    with Session(get_engine()) as db:
        assert db.scalar(select(func.count()).select_from(BusinessService)) == before
        tenant_id, workspace_id = _ids(headers)
        other_tenant, other_workspace = _ids(other)
        assert db.scalar(select(func.count()).select_from(GraphNode).where(GraphNode.workspace_id == other_workspace)) == 0
        current = db.scalar(select(GraphSnapshot).where(GraphSnapshot.workspace_id == workspace_id, GraphSnapshot.is_current.is_(True)))
        duplicate = db.scalar(select(func.count()).select_from(GraphNode).where(
            GraphNode.snapshot_id == current.id,
            GraphNode.vendor_id == "device:synth-junos-edge-01",
        ))
        assert duplicate == 1
        _ = (tenant_id, other_tenant)


def test_partial_failure_cancellation_and_manual_membership(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _workspace(f"gr-{uuid.uuid4().hex[:8]}")
    tenant_id, workspace_id = _ids(headers)
    first = client.post("/api/v1/graph/builds", headers=headers, json={"idempotency_key": "partial-base", "fixture": "nordic-retail"})
    assert first.status_code == 201, first.text
    partial = client.post("/api/v1/graph/builds", headers=headers, json={"idempotency_key": "partial-next", "fixture": "partial"})
    assert partial.status_code == 201, partial.text
    nodes = client.get("/api/v1/graph/nodes?node_type=device&limit=100", headers=headers).json()
    missing = next(item for item in nodes if item["vendor_id"] == "device:Q2XX-SYNTH-0001")
    assert missing["lifecycle"] == "missing"
    assert "omitted_by_partial_collection" in missing["limitations"]
    stale = client.get("/api/v1/graph/nodes?node_type=route", headers=headers).json()[0]
    assert stale["freshness"] == "stale"
    provenance = client.get(f"/api/v1/graph/nodes/{stale['id']}/provenance", headers=headers)
    assert provenance.status_code == 200, provenance.text
    assert provenance.json()["observations"][0]["source_contract"] == "junos-rpc-v1"
    assert provenance.json()["conflicts"]
    edges = client.get("/api/v1/graph/edges?edge_type=peers_with", headers=headers).json()
    assert edges[0]["evidence_mode"] == "inferred"
    assert edges[0]["derivation_rule"] == "shared-site-key-v1"
    neighborhood = client.get(f"/api/v1/graph/nodes/{missing['id']}?limit=1", headers=headers)
    assert neighborhood.status_code == 200, neighborhood.text
    assert "neighborhood_depth_one" in neighborhood.json()["limitations"]
    assert client.get(f"/api/v1/graph/nodes/{missing['id']}?depth=2", headers=headers).status_code == 422
    with Session(get_engine()) as db:
        current_id = uuid.UUID(partial.json()["id"])
        try:
            materialize(db, tenant_id=tenant_id, workspace_id=workspace_id, actor="admin\ninjected", idempotency_key="cancel-build-1", fixture="nordic-retail", cancelled=lambda: True)
        except GraphFailure as exc:
            assert exc.code == "cancelled"
        current = db.scalar(select(GraphSnapshot).where(GraphSnapshot.id == current_id))
        assert current is not None and current.is_current is True
        failed = db.scalar(select(GraphSnapshot).where(GraphSnapshot.workspace_id == workspace_id, GraphSnapshot.status == "cancelled"))
        assert failed is not None and failed.is_current is False
        assert "\n" not in failed.actor
        assert "<" not in failed.actor
    hidden = client.get(f"/api/v1/graph/snapshots/{failed.id}", headers=headers)
    assert hidden.status_code == 404
    assert hidden.json()["detail"] == "Graph object not found"
    monkeypatch.setenv("THREATSIGHT_KILL_SWITCH", "true")
    get_settings.cache_clear()
    blocked = client.post("/api/v1/graph/builds", headers=headers, json={"idempotency_key": "kill-build-1", "fixture": "nordic-retail"})
    assert blocked.status_code == 503
    get_settings.cache_clear()
    monkeypatch.delenv("THREATSIGHT_KILL_SWITCH", raising=False)
    get_settings.cache_clear()
    still = client.get("/api/v1/graph/snapshots/current", headers=headers)
    assert still.json()["id"] == partial.json()["id"]
    service = client.get("/api/v1/graph/services", headers=headers).json()[0]
    member = client.get("/api/v1/graph/nodes?node_type=device&limit=100", headers=headers).json()[0]
    with Session(get_engine()) as db:
        before = db.scalar(select(GraphNode).where(GraphNode.id == uuid.UUID(member["id"]))).attributes
    added = client.post(f"/api/v1/graph/services/{service['id']}/members", headers=headers, json={"member_node_id": member["id"], "role": "dependency"})
    assert added.status_code == 201, added.text
    assert added.json()["evidence_mode"] == "manual"
    with Session(get_engine()) as db:
        after = db.scalar(select(GraphNode).where(GraphNode.id == uuid.UUID(member["id"])))
        assert after.attributes == before
        audit = db.scalar(select(AuditEvent).where(AuditEvent.entity_type == "graph_member", AuditEvent.action == "added"))
        assert audit is not None
        assert "\n" not in audit.actor
        assert "<" not in str(audit.payload)
    assert client.post(f"/api/v1/graph/services/{service['id']}/members", headers=headers, json={"member_node_id": member["id"], "role": "dependency"}).status_code == 409
    with Session(get_engine()) as db:
        workspace = db.scalar(select(Workspace).where(Workspace.key == headers["X-Workspace-Key"]))
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject="graph-operator", role="operator"))
        db.commit()
    operator_headers = {"X-Actor": "graph-operator", "X-Workspace-Key": headers["X-Workspace-Key"]}
    assert client.post(f"/api/v1/graph/services/{service['id']}/members", headers=operator_headers, json={"member_node_id": member["id"], "role": "network"}).status_code == 403
    other = _workspace(f"gr-{uuid.uuid4().hex[:8]}")
    assert client.get(f"/api/v1/graph/nodes/{member['id']}", headers=other).status_code == 404
    assert client.get(f"/api/v1/graph/nodes/{uuid.uuid4()}", headers=headers).json()["detail"] == "Graph object not found"


def test_cross_workspace_jobs_and_same_source_ids_do_not_collide(client: TestClient) -> None:
    headers = _workspace(f"gr-{uuid.uuid4().hex[:8]}")
    other = _workspace(f"gr-{uuid.uuid4().hex[:8]}")
    tenant_id, workspace_id = _ids(headers)
    other_tenant, other_workspace = _ids(other)
    now = datetime.now(UTC)
    record = NormalizedRecord(
        kind="device", external_id="device:same", collected_at=now, truth_state="live_verified",
        attributes={"name": "same-name\nINJECTED"}, provenance={"contract": "device.v1"}, limitations=["synthetic_fixture"],
    )
    with Session(get_engine()) as db:
        instance = ConnectorInstance(
            tenant_id=tenant_id, workspace_id=workspace_id, connector_key="meraki.dashboard",
            name=f"meraki-{uuid.uuid4().hex[:6]}", mode="fixture", maturity="fixture_tested", status="enabled",
        )
        db.add(instance)
        db.flush()
        job = ConnectorJob(
            tenant_id=tenant_id, workspace_id=workspace_id, connector_instance_id=instance.id,
            job_type="inventory", idempotency_key=uuid.uuid4().hex, created_by="test", status="succeeded",
        )
        db.add(job)
        db.flush()
        envelope = CollectionEnvelope(
            connector_key="meraki.dashboard", job_id=str(job.id), idempotency_key=job.idempotency_key,
            sequence=0, mode="fixture", maturity="fixture_tested", records=[record], emitted_at=now,
            content_hash=CollectionEnvelope.hash_records([record]),
        )
        db.add(ConnectorJobAttempt(job_id=job.id, attempt_number=1, status="succeeded", result_envelope=envelope.model_dump(mode="json")))
        foreign = ConnectorJob(
            tenant_id=other_tenant, workspace_id=other_workspace, connector_instance_id=instance.id,
            job_type="inventory", idempotency_key=uuid.uuid4().hex, created_by="test", status="succeeded",
        )
        db.add(foreign)
        db.commit()
        job_id = job.id
        foreign_id = foreign.id
    assert client.post("/api/v1/graph/builds", headers=headers, json={"idempotency_key": "nordic-owned", "fixture": "nordic-retail"}).status_code == 201
    assert client.post("/api/v1/graph/builds", headers=other, json={"idempotency_key": "nordic-other", "fixture": "nordic-retail"}).status_code == 201
    rejected = client.post("/api/v1/graph/builds", headers=headers, json={"idempotency_key": "foreign-job-1", "job_ids": [str(foreign_id)]})
    assert rejected.status_code == 404
    assert rejected.json()["detail"] == "Graph object not found"
    built = client.post("/api/v1/graph/builds", headers=headers, json={"idempotency_key": "owned-job-1", "job_ids": [str(job_id)]})
    assert built.status_code == 201, built.text
    with Session(get_engine()) as db:
        rows = list(db.scalars(select(GraphNode).where(GraphNode.vendor_id == "device:same")))
        assert len(rows) == 1
        assert rows[0].workspace_id == workspace_id
        assert rows[0].maturity == "fixture_tested"
        assert "\n" not in rows[0].label
        ours = list(db.scalars(select(GraphNode).where(GraphNode.vendor_id == "device:synth-junos-edge-01")))
        assert {row.workspace_id for row in ours} >= {workspace_id, other_workspace}
        mixed = db.execute(text(
            "SELECT 1 FROM graph_edges e "
            "JOIN graph_nodes a ON a.id = e.from_node_id "
            "JOIN graph_nodes b ON b.id = e.to_node_id "
            "WHERE a.workspace_id <> b.workspace_id LIMIT 1"
        )).first()
        assert mixed is None


def test_database_rejects_unapproved_node_types(client: TestClient) -> None:
    _ = client
    headers = _workspace(f"gr-{uuid.uuid4().hex[:8]}")
    tenant_id, workspace_id = _ids(headers)
    with Session(get_engine()) as db:
        snapshot = GraphSnapshot(
            tenant_id=tenant_id, workspace_id=workspace_id, idempotency_key=uuid.uuid4().hex,
            status="completed", is_current=False, content_hash="1" * 64, source_fingerprint="1" * 64,
            actor="test", limitations=[],
        )
        db.add(snapshot)
        db.flush()
        db.add(GraphNode(
            tenant_id=tenant_id, workspace_id=workspace_id, snapshot_id=snapshot.id, node_type="RELATED_TO",
            source_key="bad", vendor_id="bad", label="bad", maturity="fixture_tested", evidence_mode="configured",
            connector_key="azure.resource_graph", source_contract="x.v1", source_record_id="bad",
            collected_at=datetime.now(UTC), materialized_at=datetime.now(UTC), freshness="fresh",
            confidence="stated", limitations=[], lifecycle="active", attributes={},
        ))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    with Session(get_engine()) as db:
        snapshot = GraphSnapshot(
            tenant_id=tenant_id, workspace_id=workspace_id, idempotency_key=uuid.uuid4().hex,
            status="completed", is_current=False, content_hash="2" * 64, source_fingerprint="2" * 64,
            actor="test", limitations=[],
        )
        db.add(snapshot)
        db.flush()
        origin = GraphNode(
            tenant_id=tenant_id, workspace_id=workspace_id, snapshot_id=snapshot.id, node_type="device",
            source_key="device:a", vendor_id="device:a", label="a", maturity="fixture_tested", evidence_mode="observed",
            connector_key="junos.device", source_contract="junos-rpc-v1", source_record_id="device:a",
            collected_at=datetime.now(UTC), materialized_at=datetime.now(UTC), freshness="fresh",
            confidence="stated", limitations=[], lifecycle="active", attributes={},
        )
        target = GraphNode(
            tenant_id=tenant_id, workspace_id=workspace_id, snapshot_id=snapshot.id, node_type="device",
            source_key="device:b", vendor_id="device:b", label="b", maturity="fixture_tested", evidence_mode="observed",
            connector_key="meraki.dashboard", source_contract="device.v1", source_record_id="device:b",
            collected_at=datetime.now(UTC), materialized_at=datetime.now(UTC), freshness="fresh",
            confidence="stated", limitations=[], lifecycle="active", attributes={},
        )
        db.add(origin)
        db.add(target)
        db.flush()
        db.add(GraphEdge(
            tenant_id=tenant_id, workspace_id=workspace_id, snapshot_id=snapshot.id, edge_type="peers_with",
            source_key="peers", from_node_id=origin.id, to_node_id=target.id, maturity="fixture_tested",
            evidence_mode="inferred", connector_key="junos.device", source_contract="junos-rpc-v1",
            source_record_id="device:a", collected_at=datetime.now(UTC), materialized_at=datetime.now(UTC),
            freshness="fresh", confidence="derived", limitations=[], lifecycle="active", derivation_rule=None,
            contributing=[],
        ))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        tables = set(db.scalars(text(
            "SELECT table_name FROM information_schema.columns "
            "WHERE column_name = 'tenant_id' AND table_name LIKE 'graph_%'"
        )))
    assert tables >= {"graph_snapshots", "graph_nodes", "graph_edges", "graph_observations", "graph_conflicts", "graph_service_memberships"}
