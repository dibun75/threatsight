"""Publish one correlation run for one completed graph snapshot."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatsight_api.config import get_settings
from threatsight_api.correlation.bounds import MAX_ALIASES, MAX_EVENTS
from threatsight_api.correlation.rules import CorrelationStop, correlate
from threatsight_api.correlation.vocabulary import RULESET_VERSION
from threatsight_api.graph.sanitize import GraphFailure, plain_text
from threatsight_api.graph.vocabulary import NOT_A_FINDING
from threatsight_api.persistence.models import (
    AuditEvent,
    CorrelationAlias,
    CorrelationMatch,
    CorrelationReview,
    CorrelationRun,
    GraphEdge,
    GraphNode,
    GraphServiceMembership,
    GraphSnapshot,
    ThreatCluster,
    ThreatClusterMembership,
    ThreatEvent,
    ThreatSource,
    VulnerabilitySignal,
    Workspace,
)

_EMPTY = "0" * 64
_REVIEW = {"accepted_relevant", "not_applicable", "needs_more_data", "suppressed_until"}


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
) -> CorrelationRun:
    clock = datetime.now(UTC)
    started = datetime.now(UTC)
    spent = elapsed or (lambda: (datetime.now(UTC) - started).total_seconds())
    snapshot = _snapshot(db, tenant_id, workspace_id, snapshot_id)
    if snapshot is None:
        raise GraphFailure("source_rejected")
    stop = _stop(cancelled, spent)
    if stop:
        _terminal(db, snapshot, actor, idempotency_key, stop, clock)
        raise GraphFailure(stop)
    events, threat_fingerprint, partial = _events(db)
    aliases = _alias_rows(db, tenant_id, workspace_id)
    try:
        outcome = correlate(
            events,
            _nodes(db, snapshot),
            _edges(db, snapshot),
            _memberships(db, snapshot),
            aliases,
            elapsed=spent,
            cancelled=cancelled,
        )
    except CorrelationStop as exc:
        _terminal(db, snapshot, actor, idempotency_key, exc.code, clock)
        raise GraphFailure(exc.code) from None
    if partial:
        outcome["limitations"] = sorted(set([*outcome["limitations"], "event_limit"]))
        outcome["partial"] = True
    if not snapshot.is_current:
        outcome["limitations"] = sorted(set([*outcome["limitations"], "replayed_snapshot"]))
    identity = hashlib.sha256(f"{snapshot.content_hash}:{threat_fingerprint}:{RULESET_VERSION}:{_alias_digest(aliases)}".encode()).hexdigest()
    digest = _digest(outcome)
    try:
        return _publish(db, snapshot, actor, idempotency_key, identity, threat_fingerprint, digest, outcome, clock, cancelled, spent)
    except GraphFailure as exc:
        db.rollback()
        _terminal(db, snapshot, actor, idempotency_key, exc.code, clock)
        raise


def record_review(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    match_id: uuid.UUID,
    actor: str,
    decision: str,
    reason: str,
    expires_at: datetime | None,
) -> CorrelationReview:
    if decision not in _REVIEW:
        raise GraphFailure("vocabulary_rejected")
    cleaned = plain_text(reason).strip()
    if len(cleaned) < 8 or len(cleaned) > 400:
        raise GraphFailure("vocabulary_rejected")
    match = db.scalar(select(CorrelationMatch).where(
        CorrelationMatch.id == match_id,
        CorrelationMatch.tenant_id == tenant_id,
        CorrelationMatch.workspace_id == workspace_id,
    ))
    if match is None:
        raise GraphFailure("source_rejected")
    now = datetime.now(UTC)
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if decision == "suppressed_until":
        if expires_at is None or expires_at <= now or expires_at > now + timedelta(days=90):
            raise GraphFailure("vocabulary_rejected")
    elif expires_at is not None:
        raise GraphFailure("vocabulary_rejected")
    row = CorrelationReview(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        match_key=match.match_key,
        evidence_hash=match.evidence_hash,
        decision=decision,
        reason=cleaned,
        actor=_actor(actor),
        expires_at=expires_at,
    )
    db.add(row)
    db.flush()
    db.add(AuditEvent(
        entity_type="correlation_review",
        entity_id=row.id,
        action=decision,
        actor=_actor(actor),
        payload={"match_key": match.match_key},
    ))
    db.commit()
    return row


def add_alias(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    actor: str,
    alias_vendor: str,
    alias_product: str,
    vendor: str,
    product: str,
    reason: str,
) -> CorrelationAlias:
    tokens = [_token(item) for item in (alias_vendor, alias_product, vendor, product)]
    if not all(tokens):
        raise GraphFailure("vocabulary_rejected")
    count = len(db.scalars(select(CorrelationAlias.id).where(CorrelationAlias.workspace_id == workspace_id)).all())
    if count >= MAX_ALIASES:
        raise GraphFailure("bound_exceeded")
    existing = db.scalar(select(CorrelationAlias).where(
        CorrelationAlias.workspace_id == workspace_id,
        CorrelationAlias.alias_vendor == tokens[0],
        CorrelationAlias.alias_product == tokens[1],
    ))
    if existing is not None:
        if existing.vendor != tokens[2] or existing.product != tokens[3]:
            raise GraphFailure("vocabulary_rejected")
        return existing
    row = CorrelationAlias(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        alias_vendor=tokens[0],
        alias_product=tokens[1],
        vendor=tokens[2],
        product=tokens[3],
        version="1",
        reason=plain_text(reason)[:400] or "approved alias",
        actor=_actor(actor),
    )
    db.add(row)
    db.flush()
    db.add(AuditEvent(
        entity_type="correlation_alias",
        entity_id=row.id,
        action="created",
        actor=_actor(actor),
        payload={"alias_vendor": tokens[0], "alias_product": tokens[1]},
    ))
    db.commit()
    return row


def _publish(db, snapshot, actor, idempotency_key, identity, threat_fingerprint, digest, outcome, clock, cancelled, spent) -> CorrelationRun:
    locked = db.scalar(select(Workspace.id).where(Workspace.id == snapshot.workspace_id, Workspace.tenant_id == snapshot.tenant_id).with_for_update())
    if locked is None:
        raise GraphFailure("source_rejected")
    existing = db.scalar(select(CorrelationRun).where(
        CorrelationRun.workspace_id == snapshot.workspace_id,
        CorrelationRun.tenant_id == snapshot.tenant_id,
        CorrelationRun.idempotency_key == idempotency_key,
        CorrelationRun.status == "completed",
    ))
    if existing is not None:
        if existing.snapshot_id != snapshot.id:
            raise GraphFailure("publication_race")
        return existing
    current = db.scalar(select(CorrelationRun).where(
        CorrelationRun.workspace_id == snapshot.workspace_id,
        CorrelationRun.tenant_id == snapshot.tenant_id,
        CorrelationRun.status == "completed",
        CorrelationRun.is_current.is_(True),
        CorrelationRun.identity == identity,
        CorrelationRun.snapshot_id == snapshot.id,
    ))
    if current is not None and current.content_hash == digest:
        return current
    if _stop(cancelled, spent):
        raise GraphFailure(_stop(cancelled, spent) or "cancelled")
    run = CorrelationRun(
        tenant_id=snapshot.tenant_id,
        workspace_id=snapshot.workspace_id,
        snapshot_id=snapshot.id,
        idempotency_key=idempotency_key,
        identity=identity,
        ruleset_version=outcome["ruleset_version"],
        threat_fingerprint=threat_fingerprint,
        status="building",
        is_current=False,
        content_hash=digest,
        started_at=clock,
        match_count=len(outcome["results"]),
        limitations=sorted(set([*outcome["limitations"], NOT_A_FINDING])),
        actor=_actor(actor),
    )
    db.add(run)
    db.flush()
    for item in outcome["results"]:
        if not item["asset_key"] or not item["event_ids"]:
            raise GraphFailure("vocabulary_rejected")
        db.add(CorrelationMatch(
            tenant_id=snapshot.tenant_id,
            workspace_id=snapshot.workspace_id,
            run_id=run.id,
            snapshot_id=snapshot.id,
            match_key=_match_key(item),
            evidence_hash=_evidence_hash(item),
            state=item["state"],
            rule_id=item["rule_id"],
            rule_version=item["rule_version"],
            cve=item["cve"][:20],
            asset_key=item["asset_key"][:500],
            event_ids=item["event_ids"],
            cluster_keys=item["cluster_keys"],
            sources=item["sources"],
            source_count=item["source_count"],
            services=item["services"],
            evidence_mode=item["evidence_mode"] if item["evidence_mode"] in {"observed", "configured", "inferred", "manual"} else "configured",
            maturity=item["maturity"],
            freshness=item["freshness"] if item["freshness"] in {"fresh", "stale", "untested"} else "untested",
            identifier_evidence=item["identifier_evidence"],
            version_evidence=item["version_evidence"],
            provenance=item["provenance"],
            geography=item["geography"],
            epss_score=item["epss_score"],
            epss_date=item["epss_date"],
            exploitation_status=str(item["exploitation_status"])[:32],
            limitations=sorted(set(item["limitations"])),
            missing_facts=item["missing_facts"],
            explanation=item["explanation"],
        ))
    previous = db.scalar(select(CorrelationRun).where(
        CorrelationRun.workspace_id == snapshot.workspace_id,
        CorrelationRun.tenant_id == snapshot.tenant_id,
        CorrelationRun.status == "completed",
        CorrelationRun.is_current.is_(True),
    ))
    if previous is not None:
        previous.is_current = False
        run.supersedes_id = previous.id
        db.flush()
    if _stop(cancelled, spent):
        raise GraphFailure(_stop(cancelled, spent) or "cancelled")
    run.status = "completed"
    run.is_current = True
    run.completed_at = clock
    db.add(AuditEvent(entity_type="correlation_run", entity_id=run.id, action="completed", actor=_actor(actor), payload={"matches": run.match_count}))
    try:
        db.commit()
    except IntegrityError:
        raise GraphFailure("publication_race") from None
    return run


def _events(db) -> tuple[list[dict], str, bool]:
    rows = db.execute(select(ThreatEvent, ThreatSource).join(ThreatSource, ThreatSource.id == ThreatEvent.source_id).order_by(ThreatEvent.external_id).limit(MAX_EVENTS + 1)).all()
    partial = len(rows) > MAX_EVENTS
    rows = rows[:MAX_EVENTS]
    ids = [row[0].id for row in rows]
    clusters = {}
    if ids:
        for membership, cluster in db.execute(select(ThreatClusterMembership, ThreatCluster).join(ThreatCluster, ThreatCluster.id == ThreatClusterMembership.cluster_id).where(ThreatClusterMembership.event_id.in_(ids))).all():
            clusters[membership.event_id] = cluster.key
    cves = sorted({cve for event, _source in rows for cve in (event.cves or [])})
    signals = {}
    if cves:
        for signal in db.scalars(select(VulnerabilitySignal).where(VulnerabilitySignal.cve.in_(cves[:500]))):
            signals[signal.cve] = signal
    events = []
    fingerprint = []
    for event, source in rows:
        attrs = event.attributes or {}
        cve = next((item for item in event.cves or [] if isinstance(item, str)), "")
        signal = signals.get(cve)
        events.append({
            "event_id": str(event.id),
            "cluster_key": clusters.get(event.id),
            "cves": [item for item in (event.cves or []) if isinstance(item, str)],
            "cpes": [item for item in (attrs.get("cpes") or []) if isinstance(item, str)],
            "vendors": [item for item in (event.vendors or []) if isinstance(item, str)],
            "products": [item for item in (event.products or []) if isinstance(item, str)],
            "version_ranges": [item for item in (attrs.get("version_ranges") or []) if isinstance(item, str)],
            "purls": [item for item in (attrs.get("purls") or []) if isinstance(item, str)],
            "cloud_service": attrs.get("cloud_service") if isinstance(attrs.get("cloud_service"), str) else "",
            "cloud_scope": attrs.get("cloud_scope") if isinstance(attrs.get("cloud_scope"), str) else "",
            "exploitation_status": event.exploitation_status,
            "epss_score": None if signal is None else signal.epss_score,
            "epss_date": None if signal is None or signal.score_date is None else signal.score_date.date().isoformat(),
            "freshness": "stale" if "stale_source" in (event.limitations or []) else "fresh",
            "authority_jurisdictions": list(event.authority_jurisdictions or []),
            "target_countries": list(event.target_countries or []),
            "victim_countries": list(event.victim_countries or []),
            "infrastructure_countries": list(event.infrastructure_countries or []),
            "prevalence_countries": list(event.prevalence_countries or []),
            "source_key": source.key,
            "provenance": {"parser": event.parser_version, "source": source.key},
        })
        fingerprint.append((event.external_id, event.content_hash))
    digest = hashlib.sha256(json.dumps(fingerprint, separators=(",", ":")).encode()).hexdigest()
    return events, digest, partial


def _alias_rows(db, tenant_id, workspace_id) -> list[dict]:
    rows = db.scalars(select(CorrelationAlias).where(
        CorrelationAlias.tenant_id == tenant_id,
        CorrelationAlias.workspace_id == workspace_id,
    ).order_by(CorrelationAlias.alias_vendor, CorrelationAlias.alias_product).limit(MAX_ALIASES))
    return [{"alias_vendor": row.alias_vendor, "alias_product": row.alias_product, "vendor": row.vendor, "product": row.product, "version": row.version} for row in rows]


def _nodes(db, snapshot) -> list[dict]:
    rows = db.scalars(select(GraphNode).where(GraphNode.snapshot_id == snapshot.id, GraphNode.tenant_id == snapshot.tenant_id, GraphNode.workspace_id == snapshot.workspace_id).order_by(GraphNode.source_key))
    return [{"source_key": row.source_key, "node_type": row.node_type, "connector_key": row.connector_key, "evidence_mode": row.evidence_mode, "freshness": row.freshness, "maturity": row.maturity, "attributes": dict(row.attributes or {})} for row in rows]


def _edges(db, snapshot) -> list[dict]:
    ids = {row.id: row.source_key for row in db.scalars(select(GraphNode).where(GraphNode.snapshot_id == snapshot.id))}
    rows = db.scalars(select(GraphEdge).where(GraphEdge.snapshot_id == snapshot.id, GraphEdge.tenant_id == snapshot.tenant_id, GraphEdge.workspace_id == snapshot.workspace_id).order_by(GraphEdge.source_key))
    found = []
    for row in rows:
        left, right = ids.get(row.from_node_id), ids.get(row.to_node_id)
        if left and right:
            found.append({"source_key": row.source_key, "edge_type": row.edge_type, "from_key": left, "to_key": right, "evidence_mode": row.evidence_mode})
    return found


def _memberships(db, snapshot) -> list[dict]:
    ids = {row.id: row.source_key for row in db.scalars(select(GraphNode).where(GraphNode.snapshot_id == snapshot.id))}
    rows = db.scalars(select(GraphServiceMembership).where(GraphServiceMembership.snapshot_id == snapshot.id, GraphServiceMembership.tenant_id == snapshot.tenant_id, GraphServiceMembership.workspace_id == snapshot.workspace_id))
    found = []
    for row in rows:
        service, member = ids.get(row.service_node_id), ids.get(row.member_node_id)
        if service and member:
            found.append({"service_key": service, "member_key": member, "role": row.role})
    return found


def _snapshot(db, tenant_id, workspace_id, snapshot_id) -> GraphSnapshot | None:
    return db.scalar(select(GraphSnapshot).where(GraphSnapshot.id == snapshot_id, GraphSnapshot.tenant_id == tenant_id, GraphSnapshot.workspace_id == workspace_id, GraphSnapshot.status == "completed"))


def _terminal(db, snapshot, actor, idempotency_key, code, clock) -> None:
    status = "cancelled" if code == "cancelled" else "failed"
    row = CorrelationRun(
        tenant_id=snapshot.tenant_id, workspace_id=snapshot.workspace_id, snapshot_id=snapshot.id,
        idempotency_key=idempotency_key, identity=_EMPTY, ruleset_version=RULESET_VERSION, threat_fingerprint=_EMPTY,
        status=status, is_current=False, content_hash=_EMPTY, started_at=clock, completed_at=clock,
        limitations=[NOT_A_FINDING], failure_code=code[:64], actor=_actor(actor),
    )
    db.add(row)
    db.flush()
    db.add(AuditEvent(entity_type="correlation_run", entity_id=row.id, action=status, actor=_actor(actor), payload={"code": code[:64]}))
    db.commit()


def _digest(outcome: dict) -> str:
    body = json.dumps({"limitations": outcome["limitations"], "results": outcome["results"]}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{outcome['ruleset_version']}:{body}".encode()).hexdigest()


def _alias_digest(aliases: list[dict]) -> str:
    return hashlib.sha256(json.dumps(aliases, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _match_key(item: dict) -> str:
    return hashlib.sha256(f"{item['rule_id']}|{item['cve']}|{item['asset_key']}|{RULESET_VERSION}".encode()).hexdigest()


def _evidence_hash(item: dict) -> str:
    body = json.dumps({"state": item["state"], "version": item["version_evidence"], "identifier": item["identifier_evidence"], "sources": item["source_count"]}, sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def _stop(cancelled, elapsed) -> str | None:
    if cancelled and cancelled():
        return "cancelled"
    if get_settings().kill_switch:
        return "kill_switch"
    if elapsed() > 2:
        return "bound_exceeded"
    return None


def _token(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text or len(text) > 64 or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for ch in text):
        return ""
    return text


def _actor(value: str) -> str:
    cleaned = "".join(ch for ch in str(value) if ch.isprintable() and ch not in "<>")[:200].strip()
    return cleaned or "unknown"
