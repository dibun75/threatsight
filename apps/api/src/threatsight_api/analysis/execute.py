"""Publish one analysis run for one completed graph snapshot."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatsight_api.analysis.rules import AnalysisStop, evaluate
from threatsight_api.analysis.vocabulary import RULESET_VERSION
from threatsight_api.config import get_settings
from threatsight_api.graph.sanitize import GraphFailure
from threatsight_api.graph.vocabulary import NOT_A_FINDING
from threatsight_api.persistence.models import (
    AnalysisResult,
    AnalysisRun,
    AuditEvent,
    GraphConflict,
    GraphEdge,
    GraphNode,
    GraphServiceMembership,
    GraphSnapshot,
    Workspace,
)

_EMPTY = "0" * 64


def execute(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    actor: str,
    idempotency_key: str,
    cancelled: Callable[[], bool] | None = None,
    elapsed: Callable[[], float] | None = None,
) -> AnalysisRun:
    clock = datetime.now(UTC)
    started = datetime.now(UTC)
    spent = elapsed or (lambda: (datetime.now(UTC) - started).total_seconds())
    snapshot = _snapshot(db, tenant_id, workspace_id, snapshot_id)
    if snapshot is None:
        raise GraphFailure("source_rejected")
    stop = _stop(cancelled, spent)
    if stop:
        _terminal(db, tenant_id, workspace_id, snapshot_id, actor, idempotency_key, stop, clock)
        raise GraphFailure(stop)
    try:
        outcome = evaluate(
            _nodes(db, snapshot),
            _edges(db, snapshot),
            _conflicts(db, snapshot),
            _memberships(db, snapshot),
            elapsed=spent,
            cancelled=cancelled,
        )
    except AnalysisStop as exc:
        _terminal(db, tenant_id, workspace_id, snapshot_id, actor, idempotency_key, exc.code, clock)
        raise GraphFailure(exc.code) from None
    identity = hashlib.sha256(f"{snapshot.content_hash}:{RULESET_VERSION}".encode()).hexdigest()
    digest = _digest(outcome)
    try:
        return _publish(db, snapshot, actor, idempotency_key, identity, digest, outcome, clock, cancelled, spent)
    except GraphFailure as exc:
        db.rollback()
        _terminal(db, tenant_id, workspace_id, snapshot_id, actor, idempotency_key, exc.code, clock)
        raise


def _publish(db, snapshot, actor, idempotency_key, identity, digest, outcome, clock, cancelled, spent) -> AnalysisRun:
    locked = db.scalar(select(Workspace.id).where(
        Workspace.id == snapshot.workspace_id,
        Workspace.tenant_id == snapshot.tenant_id,
    ).with_for_update())
    if locked is None:
        raise GraphFailure("source_rejected")
    existing = db.scalar(select(AnalysisRun).where(
        AnalysisRun.workspace_id == snapshot.workspace_id,
        AnalysisRun.tenant_id == snapshot.tenant_id,
        AnalysisRun.idempotency_key == idempotency_key,
        AnalysisRun.status == "completed",
    ))
    if existing is not None:
        if existing.snapshot_id != snapshot.id:
            raise GraphFailure("publication_race")
        return existing
    current = db.scalar(select(AnalysisRun).where(
        AnalysisRun.workspace_id == snapshot.workspace_id,
        AnalysisRun.tenant_id == snapshot.tenant_id,
        AnalysisRun.status == "completed",
        AnalysisRun.is_current.is_(True),
        AnalysisRun.identity == identity,
        AnalysisRun.snapshot_id == snapshot.id,
    ))
    if current is not None and current.content_hash == digest:
        return current
    stop = _stop(cancelled, spent)
    if stop:
        raise GraphFailure(stop)
    for item in outcome["results"]:
        if not item["node_keys"]:
            raise GraphFailure("vocabulary_rejected")
        if item["maturity"] not in {"synthetic", "fixture_tested", "live_verified"}:
            raise GraphFailure("vocabulary_rejected")
    before = _graph_stamp(db, snapshot)
    run = AnalysisRun(
        tenant_id=snapshot.tenant_id,
        workspace_id=snapshot.workspace_id,
        snapshot_id=snapshot.id,
        idempotency_key=idempotency_key,
        identity=identity,
        ruleset_version=outcome["ruleset_version"],
        status="building",
        is_current=False,
        content_hash=digest,
        started_at=clock,
        result_count=len(outcome["results"]),
        limitations=sorted(set([*outcome["limitations"], NOT_A_FINDING])),
        actor=_actor(actor),
    )
    db.add(run)
    db.flush()
    for item in outcome["results"]:
        db.add(AnalysisResult(
            tenant_id=snapshot.tenant_id,
            workspace_id=snapshot.workspace_id,
            run_id=run.id,
            snapshot_id=snapshot.id,
            category=item["category"],
            state=item["state"],
            rule_id=item["rule_id"],
            rule_version=item["rule_version"],
            service_key=item["service_key"],
            explanation=item["explanation"],
            evidence_modes=item["evidence_modes"],
            maturity=item["maturity"],
            freshness=item["freshness"],
            limitations=item["limitations"],
            missing_facts=item["missing_facts"],
            node_keys=item["node_keys"],
            edge_keys=item["edge_keys"],
        ))
    previous = db.scalar(select(AnalysisRun).where(
        AnalysisRun.workspace_id == snapshot.workspace_id,
        AnalysisRun.tenant_id == snapshot.tenant_id,
        AnalysisRun.status == "completed",
        AnalysisRun.is_current.is_(True),
    ))
    if previous is not None:
        previous.is_current = False
        run.supersedes_id = previous.id
        db.flush()
    if _graph_stamp(db, snapshot) != before:
        raise GraphFailure("vocabulary_rejected")
    stop = _stop(cancelled, spent)
    if stop:
        raise GraphFailure(stop)
    run.status = "completed"
    run.is_current = True
    run.completed_at = clock
    db.add(AuditEvent(
        entity_type="analysis_run",
        entity_id=run.id,
        action="completed",
        actor=_actor(actor),
        payload={"results": run.result_count, "ruleset": run.ruleset_version},
    ))
    try:
        db.commit()
    except IntegrityError:
        raise GraphFailure("publication_race") from None
    return run


def _snapshot(db, tenant_id, workspace_id, snapshot_id) -> GraphSnapshot | None:
    return db.scalar(select(GraphSnapshot).where(
        GraphSnapshot.id == snapshot_id,
        GraphSnapshot.tenant_id == tenant_id,
        GraphSnapshot.workspace_id == workspace_id,
        GraphSnapshot.status == "completed",
    ))


def _nodes(db, snapshot) -> list[dict]:
    rows = db.scalars(select(GraphNode).where(
        GraphNode.snapshot_id == snapshot.id,
        GraphNode.tenant_id == snapshot.tenant_id,
        GraphNode.workspace_id == snapshot.workspace_id,
    ).order_by(GraphNode.source_key))
    return [
        {
            "source_key": row.source_key,
            "node_type": row.node_type,
            "evidence_mode": row.evidence_mode,
            "freshness": row.freshness,
            "maturity": row.maturity,
            "attributes": dict(row.attributes or {}),
        }
        for row in rows
    ]


def _edges(db, snapshot) -> list[dict]:
    rows = db.scalars(select(GraphEdge).where(
        GraphEdge.snapshot_id == snapshot.id,
        GraphEdge.tenant_id == snapshot.tenant_id,
        GraphEdge.workspace_id == snapshot.workspace_id,
    ).order_by(GraphEdge.source_key))
    ids = {row.id: row.source_key for row in db.scalars(select(GraphNode).where(GraphNode.snapshot_id == snapshot.id))}
    found = []
    for row in rows:
        left = ids.get(row.from_node_id)
        right = ids.get(row.to_node_id)
        if left is None or right is None:
            continue
        found.append({
            "source_key": row.source_key,
            "edge_type": row.edge_type,
            "from_key": left,
            "to_key": right,
            "evidence_mode": row.evidence_mode,
            "maturity": row.maturity,
        })
    return found


def _conflicts(db, snapshot) -> list[dict]:
    rows = db.scalars(select(GraphConflict).where(
        GraphConflict.snapshot_id == snapshot.id,
        GraphConflict.tenant_id == snapshot.tenant_id,
        GraphConflict.workspace_id == snapshot.workspace_id,
    ).order_by(GraphConflict.conflict_type, GraphConflict.subject_key))
    return [{"conflict_type": row.conflict_type, "subject_key": row.subject_key, "detail_code": row.detail_code} for row in rows]


def _memberships(db, snapshot) -> list[dict]:
    rows = db.scalars(select(GraphServiceMembership).where(
        GraphServiceMembership.snapshot_id == snapshot.id,
        GraphServiceMembership.tenant_id == snapshot.tenant_id,
        GraphServiceMembership.workspace_id == snapshot.workspace_id,
    ))
    ids = {row.id: row.source_key for row in db.scalars(select(GraphNode).where(GraphNode.snapshot_id == snapshot.id))}
    found = []
    for row in rows:
        service = ids.get(row.service_node_id)
        member = ids.get(row.member_node_id)
        if service is None or member is None:
            continue
        found.append({"service_key": service, "member_key": member, "role": row.role})
    found.sort(key=lambda item: (item["role"], item["service_key"], item["member_key"]))
    return found


def _graph_stamp(db, snapshot) -> str:
    nodes = db.execute(select(GraphNode.source_key, GraphNode.evidence_mode, GraphNode.attributes).where(
        GraphNode.snapshot_id == snapshot.id,
        GraphNode.tenant_id == snapshot.tenant_id,
        GraphNode.workspace_id == snapshot.workspace_id,
    ).order_by(GraphNode.source_key)).all()
    edges = db.execute(select(GraphEdge.source_key, GraphEdge.evidence_mode).where(
        GraphEdge.snapshot_id == snapshot.id,
        GraphEdge.tenant_id == snapshot.tenant_id,
        GraphEdge.workspace_id == snapshot.workspace_id,
    ).order_by(GraphEdge.source_key)).all()
    body = json.dumps({"nodes": [(row[0], row[1], row[2]) for row in nodes], "edges": [(row[0], row[1]) for row in edges]}, sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def _terminal(db, tenant_id, workspace_id, snapshot_id, actor, idempotency_key, code, clock) -> None:
    status = "cancelled" if code == "cancelled" else "failed"
    row = AnalysisRun(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        snapshot_id=snapshot_id,
        idempotency_key=idempotency_key,
        identity=_EMPTY,
        ruleset_version=RULESET_VERSION,
        status=status,
        is_current=False,
        content_hash=_EMPTY,
        started_at=clock,
        completed_at=clock,
        limitations=[NOT_A_FINDING],
        failure_code=code[:64],
        actor=_actor(actor),
    )
    db.add(row)
    db.flush()
    db.add(AuditEvent(
        entity_type="analysis_run",
        entity_id=row.id,
        action=status,
        actor=_actor(actor),
        payload={"code": code[:64]},
    ))
    db.commit()


def _digest(outcome: dict) -> str:
    body = json.dumps(outcome["results"], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{outcome['ruleset_version']}:{body}".encode()).hexdigest()


def _stop(cancelled, elapsed) -> str | None:
    if cancelled and cancelled():
        return "cancelled"
    if get_settings().kill_switch:
        return "kill_switch"
    if elapsed() > 2:
        return "bound_exceeded"
    return None


def _actor(value: str) -> str:
    cleaned = "".join(ch for ch in str(value) if ch.isprintable() and ch not in "<>")[:200].strip()
    return cleaned or "unknown"
