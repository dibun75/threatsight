from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from threatsight_api.config import get_settings
from threatsight_api.correlation.execute import execute
from threatsight_api.correlation.fixture import reference_events
from threatsight_api.graph.materialize import materialize
from threatsight_api.graph.sanitize import GraphFailure
from threatsight_api.main import app
from threatsight_api.persistence.models import (
    CorrelationMatch,
    CorrelationRun,
    GraphSnapshot,
    ThreatCluster,
    ThreatClusterMembership,
    ThreatEvent,
    ThreatSource,
    Workspace,
    WorkspaceMembership,
)
from threatsight_api.persistence.session import get_engine

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(role: str = "workspace-admin") -> dict[str, str]:
    subject = f"co-{uuid.uuid4().hex[:8]}"
    key = f"co-{uuid.uuid4().hex[:10]}"
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


@pytest.fixture(autouse=True)
def _hide_synthetic_source(client: TestClient):
    _ = client
    _cleanup()
    yield
    _cleanup()


def _cleanup() -> None:
    with Session(get_engine()) as db:
        source = db.scalar(select(ThreatSource).where(ThreatSource.key == "synthetic-correlation"))
        if source is None:
            return
        ids = list(db.scalars(select(ThreatEvent.id).where(ThreatEvent.source_id == source.id)))
        if ids:
            db.execute(delete(ThreatClusterMembership).where(ThreatClusterMembership.event_id.in_(ids)))
            db.execute(delete(ThreatEvent).where(ThreatEvent.id.in_(ids)))
        db.execute(delete(ThreatCluster).where(ThreatCluster.algorithm_version == "p2-13.v1"))
        db.delete(source)
        db.commit()


def _events() -> None:
    with Session(get_engine()) as db:
        source = db.scalar(select(ThreatSource).where(ThreatSource.key == "synthetic-correlation"))
        if source is None:
            source = ThreatSource(key="synthetic-correlation", provider="Synthetic", authority="Test", locator="https://example.test/correlation")
            db.add(source)
            db.flush()
        clusters: dict[str, ThreatCluster] = {}
        for item in reference_events():
            external = f"000-correlation-{item['event_id']}"
            if db.scalar(select(ThreatEvent).where(ThreatEvent.external_id == external)):
                continue
            event = ThreatEvent(
                source_id=source.id,
                external_id=external,
                event_type="advisory",
                title=item["cves"][0],
                summary="synthetic",
                canonical_url="https://example.test/advisory",
                content_hash=hashlib.sha256(external.encode()).hexdigest(),
                cves=item["cves"],
                vendors=item["vendors"],
                products=item["products"],
                authority_jurisdictions=item["authority_jurisdictions"],
                target_countries=item["target_countries"],
                exploitation_status=item["exploitation_status"],
                limitations=["stale_source"] if item["freshness"] == "stale" else [],
                attributes={
                    "cpes": item["cpes"],
                    "version_ranges": item["version_ranges"],
                    "purls": item["purls"],
                    "cloud_service": item["cloud_service"],
                    "cloud_scope": item["cloud_scope"],
                },
                source_payload_hash=hashlib.sha256(external.encode()).hexdigest(),
                parser_version="p2-13.v1",
            )
            db.add(event)
            db.flush()
            if item["cluster_key"]:
                cluster = clusters.get(item["cluster_key"])
                if cluster is None:
                    cluster = ThreatCluster(key=f"{item['cluster_key']}-{uuid.uuid4().hex[:8]}", relationship_type="duplicate", title=item["cluster_key"], factors=["cve"], algorithm_version="p2-13.v1")
                    db.add(cluster)
                    db.flush()
                    clusters[item["cluster_key"]] = cluster
                db.add(ThreatClusterMembership(cluster_id=cluster.id, event_id=event.id, relationship_type="duplicate", factors=["cve"]))
        db.commit()


def test_correlation_api_is_isolated_and_reviewable(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _workspace()
    other = _workspace()
    operator = _workspace("operator")
    tenant_id, workspace_id = _ids(headers)
    with Session(get_engine()) as db:
        snapshot = materialize(db, tenant_id=tenant_id, workspace_id=workspace_id, actor=headers["X-Actor"], idempotency_key=f"graph-{uuid.uuid4().hex[:8]}", fixture="correlation")
        snapshot_id = str(snapshot.id)
    _events()
    denied = client.post("/api/v1/correlation/runs", headers=operator, json={"snapshot_id": snapshot_id, "idempotency_key": "operator-run-01"})
    assert denied.status_code == 403
    missing = client.post("/api/v1/correlation/runs", headers=headers, json={"snapshot_id": str(uuid.uuid4()), "idempotency_key": "missing-run-01"})
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Correlation object not found"
    foreign = client.post("/api/v1/correlation/runs", headers=other, json={"snapshot_id": snapshot_id, "idempotency_key": "foreign-run-01"})
    assert foreign.status_code == 404
    injected = client.post("/api/v1/correlation/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "inject-run-001", "rule": "cve~.*"})
    assert injected.status_code == 422
    alias = client.post("/api/v1/correlation/aliases", headers=headers, json={"alias_vendor": "acme", "alias_product": "synth-widget", "vendor": "acme", "product": "widget", "reason": "Approved synthetic alias"})
    assert alias.status_code == 201, alias.text
    assert client.post("/api/v1/correlation/aliases", headers=operator, json={"alias_vendor": "acme", "alias_product": "other", "vendor": "acme", "product": "widget", "reason": "Operator must not write"}).status_code == 403
    created = client.post("/api/v1/correlation/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "correlation-run-1"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["is_current"] is True
    assert body["ruleset_version"] == "p2-13.v1"
    again = client.post("/api/v1/correlation/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "correlation-run-1"})
    assert again.json()["id"] == body["id"]
    assert client.get("/api/v1/correlation/current", headers=other).status_code == 404
    matches = client.get("/api/v1/correlation/matches?cve=CVE-2024-1001&state=confirmed_identifier_match", headers=headers)
    assert matches.status_code == 200
    assert matches.json()
    assert "summary" not in matches.json()[0]
    assert matches.json()[0]["review_state"] == "unreviewed"
    match_id = matches.json()[0]["id"]
    assert client.get(f"/api/v1/correlation/matches/{match_id}", headers=other).status_code == 404
    review = client.post(f"/api/v1/correlation/matches/{match_id}/reviews", headers=headers, json={"decision": "not_applicable", "reason": "Synthetic asset is out of the operator scope"})
    assert review.status_code == 201, review.text
    assert client.get(f"/api/v1/correlation/matches/{match_id}", headers=headers).json()["review_state"] == "not_applicable"
    other_match = client.get("/api/v1/correlation/matches?state=unknown", headers=headers).json()[0]
    expiry = (datetime.now(UTC) + timedelta(days=7)).isoformat()
    suppressed = client.post(f"/api/v1/correlation/matches/{other_match['id']}/reviews", headers=headers, json={"decision": "suppressed_until", "reason": "Suppress this synthetic row for a week", "expires_at": expiry})
    assert suppressed.status_code == 201, suppressed.text
    assert client.post(f"/api/v1/correlation/matches/{match_id}/reviews", headers=operator, json={"decision": "not_applicable", "reason": "Operator must not review"}).status_code == 403
    history = client.get(f"/api/v1/correlation/matches/{match_id}/reviews", headers=headers)
    assert history.status_code == 200 and history.json()[0]["decision"] == "not_applicable"
    services = client.get("/api/v1/correlation/services", headers=headers)
    assert services.status_code == 200 and services.json()
    rules = client.get("/api/v1/correlation/rules", headers=headers)
    assert "cve-cpe-exact-v1" in rules.json()["rules"]
    with Session(get_engine()) as db:
        with pytest.raises(GraphFailure) as exc:
            execute(db, tenant_id=tenant_id, workspace_id=workspace_id, snapshot_id=uuid.UUID(snapshot_id), actor=headers["X-Actor"], idempotency_key="cancelled-correlation", cancelled=lambda: True)
        assert exc.value.code == "cancelled"
    monkeypatch.setenv("THREATSIGHT_KILL_SWITCH", "true")
    get_settings.cache_clear()
    try:
        blocked = client.post("/api/v1/correlation/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "killed-correlation"})
        assert blocked.status_code == 503
    finally:
        monkeypatch.delenv("THREATSIGHT_KILL_SWITCH", raising=False)
        get_settings.cache_clear()
    assert client.get("/api/v1/correlation/current", headers=headers).json()["id"] == body["id"]
    with Session(get_engine()) as db:
        cancelled = db.scalar(select(CorrelationRun).where(CorrelationRun.workspace_id == workspace_id, CorrelationRun.status == "cancelled"))
        assert cancelled is not None and cancelled.is_current is False


def test_alias_conflict_replay_and_changed_evidence(client: TestClient) -> None:
    headers = _workspace()
    tenant_id, workspace_id = _ids(headers)
    with Session(get_engine()) as db:
        first = materialize(db, tenant_id=tenant_id, workspace_id=workspace_id, actor=headers["X-Actor"], idempotency_key=f"graph-{uuid.uuid4().hex[:8]}", fixture="correlation")
        first_id = str(first.id)
    _events()
    alias = {"alias_vendor": "acme", "alias_product": "synth-widget", "vendor": "acme", "product": "widget", "reason": "Approved synthetic alias"}
    assert client.post("/api/v1/correlation/aliases", headers=headers, json=alias).status_code == 201
    conflict = dict(alias)
    conflict["product"] = "other"
    assert client.post("/api/v1/correlation/aliases", headers=headers, json=conflict).status_code == 422
    created = client.post("/api/v1/correlation/runs", headers=headers, json={"snapshot_id": first_id, "idempotency_key": "security-run-0001"})
    assert created.status_code == 201, created.text
    match_id = client.get("/api/v1/correlation/matches?cve=CVE-2024-1001", headers=headers).json()[0]["id"]
    assert client.post(f"/api/v1/correlation/matches/{match_id}/reviews", headers=headers, json={"decision": "not_applicable", "reason": "Synthetic asset is out of the operator scope"}).status_code == 201
    with Session(get_engine()) as db:
        row = db.get(CorrelationMatch, uuid.UUID(match_id))
        assert row is not None
        row.evidence_hash = "0" * 64
        db.commit()
    changed = client.get(f"/api/v1/correlation/matches/{match_id}", headers=headers).json()
    assert changed["review_state"] == "unreviewed"
    assert "review_evidence_changed" in changed["limitations"]
    with Session(get_engine()) as db:
        stored = db.get(GraphSnapshot, uuid.UUID(first_id))
        assert stored is not None
        stored.is_current = False
        db.commit()
    replay = client.post("/api/v1/correlation/runs", headers=headers, json={"snapshot_id": first_id, "idempotency_key": "security-replay-01"})
    assert replay.status_code == 201, replay.text
    assert "replayed_snapshot" in replay.json()["limitations"]


def test_cancelled_snapshot_is_rejected(client: TestClient) -> None:
    headers = _workspace()
    tenant_id, workspace_id = _ids(headers)
    with Session(get_engine()) as db:
        with pytest.raises(GraphFailure):
            materialize(db, tenant_id=tenant_id, workspace_id=workspace_id, actor=headers["X-Actor"], idempotency_key="cancelled-graph-co", fixture="correlation", cancelled=lambda: True)
        rejected = db.scalar(select(GraphSnapshot).where(GraphSnapshot.workspace_id == workspace_id, GraphSnapshot.status == "cancelled"))
        assert rejected is not None
        snapshot_id = str(rejected.id)
    response = client.post("/api/v1/correlation/runs", headers=headers, json={"snapshot_id": snapshot_id, "idempotency_key": "reject-cancelled"})
    assert response.status_code == 404
    assert response.json()["detail"] == "Correlation object not found"
