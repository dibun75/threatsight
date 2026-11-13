"""Publish an immutable graph snapshot from normalized connector records."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatsight_api.config import get_settings
from threatsight_api.connectors.sdk import CollectionEnvelope
from threatsight_api.graph.bounds import (
    MAX_BUILD_SECONDS,
    MAX_EDGES,
    MAX_JOBS,
    MAX_MEMBERSHIPS,
    MAX_NODES,
    MAX_OBSERVATIONS,
)
from threatsight_api.graph.fixture import FixtureBundle, load_fixture
from threatsight_api.graph.project import Projection, content_hash, project
from threatsight_api.graph.sanitize import GraphFailure, clean_label
from threatsight_api.graph.vocabulary import NOT_A_FINDING
from threatsight_api.persistence.models import (
    AuditEvent,
    ConnectorInstance,
    ConnectorJob,
    ConnectorJobAttempt,
    GraphConflict,
    GraphEdge,
    GraphNode,
    GraphObservation,
    GraphServiceMembership,
    GraphSnapshot,
    Workspace,
)

_EMPTY_HASH = "0" * 64


def materialize(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    actor: str,
    idempotency_key: str,
    fixture: str | None = None,
    job_ids: list[uuid.UUID] | None = None,
    now: datetime | None = None,
    cancelled: Callable[[], bool] | None = None,
    elapsed: Callable[[], float] | None = None,
) -> GraphSnapshot:
    if bool(fixture) == bool(job_ids):
        raise GraphFailure("fixture_rejected")
    clock = now or datetime.now(UTC)
    started = datetime.now(UTC)
    spent = elapsed or (lambda: (datetime.now(UTC) - started).total_seconds())
    stop = _stop_code(cancelled, spent)
    if stop:
        _record_terminal(db, tenant_id, workspace_id, actor, idempotency_key, stop, clock)
        raise GraphFailure(stop)
    bundle, records = _inputs(db, tenant_id, workspace_id, fixture, job_ids or [])
    try:
        projected = project(
            records,
            now=clock,
            memberships=bundle.memberships if bundle else [],
            dependency_pairs=bundle.dependency_pairs if bundle else [],
            partial=bool(bundle and bundle.partial),
            actor=actor,
        )
    except GraphFailure as exc:
        _record_terminal(db, tenant_id, workspace_id, actor, idempotency_key, exc.code, clock)
        raise
    fingerprint = _fingerprint(records)
    try:
        return _publish(
            db, tenant_id, workspace_id, actor, idempotency_key, projected, fingerprint, clock, cancelled, spent,
        )
    except GraphFailure as exc:
        db.rollback()
        _record_terminal(db, tenant_id, workspace_id, actor, idempotency_key, exc.code, clock)
        raise


def add_membership(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    actor: str,
    service_node_id: uuid.UUID,
    member_node_id: uuid.UUID,
    role: str,
    now: datetime | None = None,
) -> GraphServiceMembership:
    clock = now or datetime.now(UTC)
    current = _current(db, tenant_id, workspace_id)
    if current is None:
        raise GraphFailure("source_rejected")
    service = _node(db, current, service_node_id)
    member = _node(db, current, member_node_id)
    if service is None or member is None or service.node_type != "business_service":
        raise GraphFailure("source_rejected")
    before = dict(member.attributes)
    row = GraphServiceMembership(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        snapshot_id=current.id,
        service_node_id=service.id,
        member_node_id=member.id,
        role=role,
        evidence_mode="manual",
        maturity="synthetic",
        derivation_rule=None,
        limitations=[NOT_A_FINDING, "manual_membership"],
        actor=_actor(actor),
        scoped_at=clock,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise GraphFailure("membership_exists") from None
    member.attributes = before
    db.add(AuditEvent(
        entity_type="graph_member",
        entity_id=row.id,
        action="added",
        actor=_actor(actor),
        payload={"role": role},
    ))
    db.commit()
    return row


def _publish(db, tenant_id, workspace_id, actor, idempotency_key, projected, fingerprint, clock, cancelled, spent) -> GraphSnapshot:
    _lock(db, tenant_id, workspace_id)
    existing = db.scalar(select(GraphSnapshot).where(
        GraphSnapshot.workspace_id == workspace_id,
        GraphSnapshot.tenant_id == tenant_id,
        GraphSnapshot.idempotency_key == idempotency_key,
        GraphSnapshot.status == "completed",
    ))
    if existing is not None:
        return existing
    if projected.partial:
        _carry_forward(db, tenant_id, workspace_id, projected, clock)
    if len(projected.nodes) > MAX_NODES or len(projected.edges) > MAX_EDGES or len(projected.observations) > MAX_OBSERVATIONS or len(projected.memberships) > MAX_MEMBERSHIPS:
        raise GraphFailure("bound_exceeded")
    stop = _stop_code(cancelled, spent)
    if stop:
        raise GraphFailure(stop)
    previous = _current(db, tenant_id, workspace_id)
    snapshot = GraphSnapshot(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        idempotency_key=idempotency_key,
        status="building",
        is_current=False,
        content_hash=content_hash(projected),
        source_fingerprint=fingerprint,
        started_at=clock,
        node_count=len(projected.nodes),
        edge_count=len(projected.edges),
        limitations=projected.limitations,
        actor=_actor(actor),
    )
    db.add(snapshot)
    db.flush()
    ids = _insert_graph(db, snapshot, projected, clock)
    if previous is not None:
        previous.is_current = False
        snapshot.supersedes_id = previous.id
        db.flush()
    snapshot.status = "completed"
    snapshot.is_current = True
    snapshot.completed_at = clock
    snapshot.materialized_at = clock
    db.add(AuditEvent(
        entity_type="graph_snapshot",
        entity_id=snapshot.id,
        action="completed",
        actor=_actor(actor),
        payload={"nodes": snapshot.node_count, "edges": snapshot.edge_count},
    ))
    try:
        db.commit()
    except IntegrityError:
        raise GraphFailure("publication_race") from None
    _ = ids
    return snapshot


def _carry_forward(db, tenant_id, workspace_id, projected: Projection, clock: datetime) -> None:
    previous = _current(db, tenant_id, workspace_id)
    if previous is None:
        projected.limitations = sorted(set([*projected.limitations, "partial_collection", NOT_A_FINDING]))
        return
    present = {node["source_key"] for node in projected.nodes}
    rows = db.scalars(select(GraphNode).where(
        GraphNode.snapshot_id == previous.id,
        GraphNode.tenant_id == tenant_id,
        GraphNode.workspace_id == workspace_id,
    ))
    for row in rows:
        if row.source_key in present:
            continue
        projected.nodes.append({
            "source_key": row.source_key,
            "node_type": row.node_type,
            "vendor_id": row.vendor_id,
            "label": row.label,
            "maturity": row.maturity,
            "evidence_mode": row.evidence_mode,
            "connector_key": row.connector_key,
            "source_contract": row.source_contract,
            "source_record_id": row.source_record_id,
            "collected_at": row.collected_at,
            "materialized_at": clock,
            "freshness": row.freshness,
            "confidence": row.confidence,
            "limitations": sorted(set([*list(row.limitations or []), "omitted_by_partial_collection"])),
            "lifecycle": "missing",
            "attributes": row.attributes,
        })
        projected.conflicts.append({
            "subject_key": row.source_key,
            "conflict_type": "partial_omission",
            "detail_code": "omitted_by_partial_collection",
            "limitations": [NOT_A_FINDING],
        })
    projected.limitations = sorted(set([*projected.limitations, "partial_collection"]))
    projected.nodes.sort(key=lambda item: (item["node_type"], item["source_key"]))
    projected.conflicts.sort(key=lambda item: (item["conflict_type"], item["subject_key"], item["detail_code"]))


def _insert_graph(db, snapshot: GraphSnapshot, projected: Projection, clock: datetime) -> dict[str, uuid.UUID]:
    ids: dict[str, uuid.UUID] = {}
    scope = {"tenant_id": snapshot.tenant_id, "workspace_id": snapshot.workspace_id, "snapshot_id": snapshot.id}
    for node in projected.nodes:
        row = GraphNode(**scope, **_node_columns(node, clock))
        db.add(row)
        db.flush()
        ids[node["source_key"]] = row.id
    for edge in projected.edges:
        if edge["evidence_mode"] == "inferred" and not edge.get("derivation_rule"):
            raise GraphFailure("vocabulary_rejected")
        from_id = ids.get(edge["from_key"])
        to_id = ids.get(edge["to_key"])
        if from_id is None or to_id is None:
            raise GraphFailure("vocabulary_rejected")
        db.add(GraphEdge(**scope, **_edge_columns(edge, from_id, to_id, clock)))
    for item in projected.observations:
        db.add(GraphObservation(
            **scope,
            subject_key=item["subject_key"],
            connector_key=item["connector_key"],
            source_contract=item["source_contract"],
            source_record_id=item["source_record_id"],
            evidence_mode=item["evidence_mode"],
            maturity=item["maturity"],
            collected_at=item["collected_at"],
            materialized_at=clock,
            payload=item["payload"],
        ))
    for item in projected.conflicts:
        db.add(GraphConflict(**scope, conflict_type=item["conflict_type"], subject_key=item["subject_key"], detail_code=item["detail_code"], limitations=item["limitations"]))
    for item in projected.memberships:
        service_id = ids.get(item["service_key"])
        member_id = ids.get(item["member_key"])
        if service_id is None or member_id is None:
            raise GraphFailure("vocabulary_rejected")
        db.add(GraphServiceMembership(
            **scope,
            service_node_id=service_id,
            member_node_id=member_id,
            role=item["role"],
            evidence_mode="manual",
            maturity="synthetic",
            derivation_rule=item.get("derivation_rule"),
            limitations=item["limitations"],
            actor=item["actor"],
            scoped_at=clock,
        ))
    db.flush()
    return ids


def _inputs(db, tenant_id, workspace_id, fixture: str | None, job_ids: list[uuid.UUID]) -> tuple[FixtureBundle | None, list[dict]]:
    if fixture:
        bundle = load_fixture(fixture)
        return bundle, [_owned(record, tenant_id, workspace_id) for record in bundle.records]
    if len(job_ids) > MAX_JOBS:
        raise GraphFailure("bound_exceeded")
    records: list[dict] = []
    for job_id in job_ids:
        records.extend(_job_records(db, tenant_id, workspace_id, job_id))
    if len(records) > MAX_NODES:
        raise GraphFailure("bound_exceeded")
    return None, records


def _job_records(db, tenant_id, workspace_id, job_id: uuid.UUID) -> list[dict]:
    job = db.scalar(select(ConnectorJob).where(
        ConnectorJob.id == job_id,
        ConnectorJob.tenant_id == tenant_id,
        ConnectorJob.workspace_id == workspace_id,
        ConnectorJob.status == "succeeded",
    ))
    if job is None:
        raise GraphFailure("source_rejected")
    instance = db.scalar(select(ConnectorInstance).where(
        ConnectorInstance.id == job.connector_instance_id,
        ConnectorInstance.tenant_id == tenant_id,
        ConnectorInstance.workspace_id == workspace_id,
    ))
    attempt = db.scalar(select(ConnectorJobAttempt).where(
        ConnectorJobAttempt.job_id == job.id,
        ConnectorJobAttempt.status == "succeeded",
    ).order_by(ConnectorJobAttempt.attempt_number.desc()))
    if instance is None or attempt is None or not attempt.result_envelope:
        raise GraphFailure("source_rejected")
    try:
        envelope = CollectionEnvelope.model_validate(attempt.result_envelope)
    except Exception:
        raise GraphFailure("source_rejected") from None
    if envelope.connector_key != instance.connector_key:
        raise GraphFailure("source_rejected")
    records = []
    for item in envelope.records:
        raw = item.model_dump(mode="json")
        raw["connector_key"] = envelope.connector_key
        raw["envelope_maturity"] = envelope.maturity
        raw["envelope_mode"] = envelope.mode
        raw["contract"] = str((item.provenance or {}).get("contract") or (item.provenance or {}).get("query") or envelope.connector_key)
        records.append(_owned(raw, tenant_id, workspace_id))
    return records


def _owned(record: dict, tenant_id: uuid.UUID, workspace_id: uuid.UUID) -> dict:
    attributes = record.get("attributes") or {}
    if "tenant_id" in attributes and str(attributes["tenant_id"]) != str(tenant_id):
        raise GraphFailure("tenant_mismatch")
    if "workspace_id" in attributes and str(attributes["workspace_id"]) != str(workspace_id):
        raise GraphFailure("tenant_mismatch")
    return record


def _node_columns(node: dict, clock: datetime) -> dict:
    return {
        "node_type": node["node_type"],
        "source_key": node["source_key"],
        "vendor_id": node["vendor_id"][:500],
        "label": clean_label(node["label"]),
        "maturity": node["maturity"],
        "evidence_mode": node["evidence_mode"],
        "connector_key": node["connector_key"],
        "source_contract": node["source_contract"],
        "source_record_id": node["source_record_id"],
        "collected_at": node["collected_at"],
        "materialized_at": clock,
        "freshness": node["freshness"],
        "confidence": node["confidence"],
        "limitations": node["limitations"],
        "lifecycle": node["lifecycle"],
        "attributes": node["attributes"],
    }


def _edge_columns(edge: dict, from_id: uuid.UUID, to_id: uuid.UUID, clock: datetime) -> dict:
    return {
        "edge_type": edge["edge_type"],
        "source_key": edge["source_key"][:500],
        "from_node_id": from_id,
        "to_node_id": to_id,
        "maturity": edge["maturity"],
        "evidence_mode": edge["evidence_mode"],
        "connector_key": edge["connector_key"],
        "source_contract": edge["source_contract"],
        "source_record_id": edge["source_record_id"],
        "collected_at": edge["collected_at"],
        "materialized_at": clock,
        "freshness": edge["freshness"],
        "confidence": edge["confidence"],
        "limitations": edge["limitations"],
        "lifecycle": edge["lifecycle"],
        "derivation_rule": edge.get("derivation_rule"),
        "derivation_version": edge.get("derivation_version"),
        "contributing": edge.get("contributing") or [],
    }


def _record_terminal(db, tenant_id, workspace_id, actor, idempotency_key, code: str, clock: datetime) -> None:
    status = "cancelled" if code == "cancelled" else "failed"
    row = GraphSnapshot(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        idempotency_key=idempotency_key,
        status=status,
        is_current=False,
        content_hash=_EMPTY_HASH,
        source_fingerprint=_EMPTY_HASH,
        started_at=clock,
        completed_at=clock,
        limitations=[NOT_A_FINDING],
        failure_code=code[:64],
        actor=_actor(actor),
    )
    db.add(row)
    db.flush()
    db.add(AuditEvent(
        entity_type="graph_snapshot",
        entity_id=row.id,
        action=status,
        actor=_actor(actor),
        payload={"code": code[:64]},
    ))
    db.commit()


def _current(db, tenant_id, workspace_id) -> GraphSnapshot | None:
    return db.scalar(select(GraphSnapshot).where(
        GraphSnapshot.tenant_id == tenant_id,
        GraphSnapshot.workspace_id == workspace_id,
        GraphSnapshot.status == "completed",
        GraphSnapshot.is_current.is_(True),
    ))


def _node(db, snapshot: GraphSnapshot, node_id: uuid.UUID) -> GraphNode | None:
    return db.scalar(select(GraphNode).where(
        GraphNode.id == node_id,
        GraphNode.snapshot_id == snapshot.id,
        GraphNode.tenant_id == snapshot.tenant_id,
        GraphNode.workspace_id == snapshot.workspace_id,
    ))


def _lock(db, tenant_id, workspace_id) -> None:
    locked = db.scalar(select(Workspace.id).where(Workspace.id == workspace_id, Workspace.tenant_id == tenant_id).with_for_update())
    if locked is None:
        raise GraphFailure("source_rejected")


def _stop_code(cancelled: Callable[[], bool] | None, elapsed: Callable[[], float]) -> str | None:
    if cancelled and cancelled():
        return "cancelled"
    if get_settings().kill_switch:
        return "kill_switch"
    if elapsed() > MAX_BUILD_SECONDS:
        return "bound_exceeded"
    return None


def _fingerprint(records: list[dict]) -> str:
    body = json.dumps(
        sorted((str(item.get("connector_key")), str(item.get("external_id")), str(item.get("kind"))) for item in records),
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode()).hexdigest()


def _actor(value: str) -> str:
    cleaned = "".join(ch for ch in str(value) if ch.isprintable() and ch not in "<>")[:200].strip()
    return cleaned or "unknown"
