"""Workspace-scoped correlation. Clients cannot supply match expressions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from threatsight_api.api.deps import DbSession, Limit, Offset, WorkspaceScope
from threatsight_api.correlation.bounds import (
    MAX_COMPARISONS,
    MAX_DEPTH,
    MAX_EVENTS,
    MAX_MATCHES_PER_ASSET,
    MAX_MATCHES_PER_EVENT,
    MAX_NODES,
    MAX_RESULTS,
    MAX_SECONDS,
)
from threatsight_api.correlation.execute import add_alias, execute, record_review
from threatsight_api.correlation.vocabulary import GLOBAL_LIMITATIONS, REVIEW_STATES, RULESET_VERSION, STATES
from threatsight_api.graph.sanitize import GraphFailure, plain_text
from threatsight_api.persistence.models import CorrelationMatch, CorrelationReview, CorrelationRun

router = APIRouter(prefix="/correlation", tags=["correlation"])
_NOT_FOUND = "Correlation object not found"
ADMIN_ROLES = frozenset({"workspace-admin", "platform-admin"})
State = Literal[
    "confirmed_identifier_match",
    "version_supported_candidate",
    "possible_match",
    "unknown",
    "conflicting",
    "not_applicable_by_evidence",
]
Review = Literal["unreviewed", "accepted_relevant", "not_applicable", "needs_more_data", "suppressed_until"]
Freshness = Literal["fresh", "stale", "untested"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunIn(StrictModel):
    snapshot_id: uuid.UUID
    idempotency_key: str = Field(min_length=8, max_length=200, pattern=r"^[A-Za-z0-9_.:-]{8,200}$")


class ReviewIn(StrictModel):
    decision: Literal["accepted_relevant", "not_applicable", "needs_more_data", "suppressed_until"]
    reason: str = Field(min_length=8, max_length=400)
    expires_at: datetime | None = None


class AliasIn(StrictModel):
    alias_vendor: str = Field(min_length=1, max_length=64)
    alias_product: str = Field(min_length=1, max_length=64)
    vendor: str = Field(min_length=1, max_length=64)
    product: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=8, max_length=400)


def _fail(exc: GraphFailure) -> HTTPException:
    if exc.code == "source_rejected":
        return HTTPException(status_code=404, detail=_NOT_FOUND)
    if exc.code == "kill_switch":
        return HTTPException(status_code=503, detail="kill_switch")
    if exc.code in {"cancelled", "publication_race"}:
        return HTTPException(status_code=409, detail=exc.code)
    return HTTPException(status_code=422, detail=exc.code)


def _run(row: CorrelationRun) -> dict:
    return {
        "id": str(row.id),
        "snapshot_id": str(row.snapshot_id),
        "ruleset_version": row.ruleset_version,
        "identity": row.identity,
        "threat_fingerprint": row.threat_fingerprint,
        "status": row.status,
        "is_current": row.is_current,
        "content_hash": row.content_hash,
        "started_at": row.started_at.isoformat(),
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "match_count": row.match_count,
        "limitations": row.limitations,
        "supersedes_id": str(row.supersedes_id) if row.supersedes_id else None,
    }


def _review_state(db, match: CorrelationMatch) -> tuple[str, list[str]]:
    row = db.scalar(select(CorrelationReview).where(
        CorrelationReview.match_key == match.match_key,
        CorrelationReview.tenant_id == match.tenant_id,
        CorrelationReview.workspace_id == match.workspace_id,
    ).order_by(CorrelationReview.created_at.desc(), CorrelationReview.id.desc()))
    if row is None:
        return "unreviewed", []
    if row.expires_at is not None and row.expires_at <= datetime.now(UTC):
        return "unreviewed", ["review_expired"]
    if row.evidence_hash != match.evidence_hash:
        return "unreviewed", ["review_evidence_changed"]
    return row.decision, []


def _match(db, row: CorrelationMatch) -> dict:
    review, extra = _review_state(db, row)
    return {
        "id": str(row.id),
        "run_id": str(row.run_id),
        "snapshot_id": str(row.snapshot_id),
        "state": row.state,
        "rule_id": row.rule_id,
        "rule_version": row.rule_version,
        "cve": row.cve,
        "asset_key": plain_text(row.asset_key),
        "event_ids": row.event_ids,
        "cluster_keys": row.cluster_keys,
        "sources": row.sources,
        "source_count": row.source_count,
        "services": row.services,
        "evidence_mode": row.evidence_mode,
        "maturity": row.maturity,
        "freshness": row.freshness,
        "identifier_evidence": row.identifier_evidence,
        "version_evidence": row.version_evidence,
        "provenance": row.provenance,
        "geography": row.geography,
        "epss_score": row.epss_score,
        "epss_date": row.epss_date,
        "exploitation_status": row.exploitation_status,
        "limitations": sorted(set([*row.limitations, *extra])),
        "missing_facts": [plain_text(str(item)) for item in row.missing_facts],
        "explanation": plain_text(row.explanation),
        "review_state": review,
    }


def _completed(db, workspace, run_id: uuid.UUID) -> CorrelationRun:
    row = db.scalar(select(CorrelationRun).where(
        CorrelationRun.id == run_id,
        CorrelationRun.tenant_id == workspace.tenant_id,
        CorrelationRun.workspace_id == workspace.id,
        CorrelationRun.status == "completed",
    ))
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


def _current(db, workspace) -> CorrelationRun:
    row = db.scalar(select(CorrelationRun).where(
        CorrelationRun.tenant_id == workspace.tenant_id,
        CorrelationRun.workspace_id == workspace.id,
        CorrelationRun.status == "completed",
        CorrelationRun.is_current.is_(True),
    ))
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


@router.post("/runs", status_code=201)
def start_run(payload: RunIn, workspace: WorkspaceScope, db: DbSession) -> dict:
    if workspace.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    try:
        row = execute(db, tenant_id=workspace.tenant_id, workspace_id=workspace.id, snapshot_id=payload.snapshot_id, actor=workspace.subject, idempotency_key=payload.idempotency_key)
    except GraphFailure as exc:
        raise _fail(exc) from None
    return _run(row)


@router.get("/runs")
def list_runs(workspace: WorkspaceScope, db: DbSession, limit: Limit = 50, offset: Offset = 0) -> list[dict]:
    rows = db.scalars(select(CorrelationRun).where(
        CorrelationRun.tenant_id == workspace.tenant_id,
        CorrelationRun.workspace_id == workspace.id,
        CorrelationRun.status.in_(("completed", "failed", "cancelled")),
    ).order_by(CorrelationRun.created_at.desc(), CorrelationRun.id).limit(limit).offset(offset))
    return [_run(row) for row in rows]


@router.get("/current")
def current_run(workspace: WorkspaceScope, db: DbSession) -> dict:
    return _run(_current(db, workspace))


@router.get("/rules")
def list_rules(workspace: WorkspaceScope) -> dict:
    _ = workspace
    return {
        "ruleset_version": RULESET_VERSION,
        "states": list(STATES),
        "review_states": list(REVIEW_STATES),
        "limitations": list(GLOBAL_LIMITATIONS),
        "bounds": {
            "max_events": MAX_EVENTS,
            "max_nodes": MAX_NODES,
            "max_comparisons": MAX_COMPARISONS,
            "max_matches_per_event": MAX_MATCHES_PER_EVENT,
            "max_matches_per_asset": MAX_MATCHES_PER_ASSET,
            "max_depth": MAX_DEPTH,
            "max_results": MAX_RESULTS,
            "max_seconds": MAX_SECONDS,
        },
        "rules": [
            "cve-cpe-exact-v1",
            "cve-version-range-v1",
            "vendor-product-alias-v1",
            "meraki-firmware-v1",
            "junos-version-v1",
            "software-identifier-v1",
            "cloud-service-advisory-v1",
        ],
    }


@router.get("/matches")
def list_matches(
    workspace: WorkspaceScope,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    run_id: uuid.UUID | None = None,
    state: State | None = None,
    cve: str | None = None,
    source: str | None = None,
    asset: str | None = None,
    service: str | None = None,
    freshness: Freshness | None = None,
    review: Review | None = None,
) -> list[dict]:
    run = _completed(db, workspace, run_id) if run_id else _current(db, workspace)
    query = select(CorrelationMatch).where(
        CorrelationMatch.run_id == run.id,
        CorrelationMatch.tenant_id == workspace.tenant_id,
        CorrelationMatch.workspace_id == workspace.id,
    )
    if state:
        query = query.where(CorrelationMatch.state == state)
    if cve:
        query = query.where(CorrelationMatch.cve == cve[:20])
    if source:
        query = query.where(CorrelationMatch.sources.contains([source[:64]]))
    if asset:
        query = query.where(CorrelationMatch.asset_key == asset[:500])
    if service:
        query = query.where(CorrelationMatch.services.contains([{"source_key": service[:500]}]))
    if freshness:
        query = query.where(CorrelationMatch.freshness == freshness)
    rows = list(db.scalars(query.order_by(CorrelationMatch.cve, CorrelationMatch.asset_key, CorrelationMatch.id)))
    if review:
        rows = [row for row in rows if _review_state(db, row)[0] == review]
    return [_match(db, row) for row in rows[offset:offset + limit]]


@router.get("/matches/{match_id}")
def get_match(match_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = db.scalar(select(CorrelationMatch).where(
        CorrelationMatch.id == match_id,
        CorrelationMatch.tenant_id == workspace.tenant_id,
        CorrelationMatch.workspace_id == workspace.id,
    ))
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    _completed(db, workspace, row.run_id)
    return _match(db, row)


@router.get("/services")
def list_services(workspace: WorkspaceScope, db: DbSession, limit: Limit = 50, offset: Offset = 0) -> list[dict]:
    run = _current(db, workspace)
    rows = db.scalars(select(CorrelationMatch).where(
        CorrelationMatch.run_id == run.id,
        CorrelationMatch.tenant_id == workspace.tenant_id,
        CorrelationMatch.workspace_id == workspace.id,
    ).order_by(CorrelationMatch.cve, CorrelationMatch.asset_key).limit(limit).offset(offset))
    return [item for item in (_match(db, row) for row in rows) if item["services"]]


@router.post("/matches/{match_id}/reviews", status_code=201)
def create_review(match_id: uuid.UUID, payload: ReviewIn, workspace: WorkspaceScope, db: DbSession) -> dict:
    if workspace.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    try:
        row = record_review(
            db,
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
            match_id=match_id,
            actor=workspace.subject,
            decision=payload.decision,
            reason=payload.reason,
            expires_at=payload.expires_at,
        )
    except GraphFailure as exc:
        raise _fail(exc) from None
    return {"id": str(row.id), "decision": row.decision, "reason": plain_text(row.reason), "expires_at": row.expires_at.isoformat() if row.expires_at else None}


@router.get("/matches/{match_id}/reviews")
def list_reviews(match_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, limit: Limit = 50, offset: Offset = 0) -> list[dict]:
    match = db.scalar(select(CorrelationMatch).where(CorrelationMatch.id == match_id, CorrelationMatch.tenant_id == workspace.tenant_id, CorrelationMatch.workspace_id == workspace.id))
    if match is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    rows = db.scalars(select(CorrelationReview).where(
        CorrelationReview.match_key == match.match_key,
        CorrelationReview.tenant_id == workspace.tenant_id,
        CorrelationReview.workspace_id == workspace.id,
    ).order_by(CorrelationReview.created_at.desc()).limit(limit).offset(offset))
    return [{"id": str(row.id), "decision": row.decision, "reason": plain_text(row.reason), "actor": plain_text(row.actor), "expires_at": row.expires_at.isoformat() if row.expires_at else None} for row in rows]


@router.post("/aliases", status_code=201)
def create_alias(payload: AliasIn, workspace: WorkspaceScope, db: DbSession) -> dict:
    if workspace.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    try:
        row = add_alias(db, tenant_id=workspace.tenant_id, workspace_id=workspace.id, actor=workspace.subject, alias_vendor=payload.alias_vendor, alias_product=payload.alias_product, vendor=payload.vendor, product=payload.product, reason=payload.reason)
    except GraphFailure as exc:
        raise _fail(exc) from None
    return {"id": str(row.id), "alias_vendor": row.alias_vendor, "alias_product": row.alias_product, "vendor": row.vendor, "product": row.product, "version": row.version}
