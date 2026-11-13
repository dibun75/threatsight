"""Workspace-scoped analysis reads. Clients cannot supply rules or traversals."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select

from threatsight_api.analysis.bounds import (
    MAX_DEPTH,
    MAX_FANOUT,
    MAX_INSPECTED,
    MAX_PATHS,
    MAX_SECONDS,
)
from threatsight_api.analysis.execute import execute
from threatsight_api.analysis.rules import RULES
from threatsight_api.analysis.vocabulary import CATEGORIES, GLOBAL_LIMITATIONS, RULESET_VERSION, STATES
from threatsight_api.api.deps import DbSession, Limit, Offset, WorkspaceScope
from threatsight_api.graph.sanitize import GraphFailure, plain_text
from threatsight_api.persistence.models import AnalysisResult, AnalysisRun, GraphNode

router = APIRouter(prefix="/analysis", tags=["analysis"])
_NOT_FOUND = "Analysis object not found"
ADMIN_ROLES = frozenset({"workspace-admin", "platform-admin"})
Category = Literal[
    "internet_exposure_candidate",
    "management_plane_candidate",
    "privileged_identity_path",
    "cross_domain_service_path",
    "contradiction_gap",
]
State = Literal["supported_candidate", "unknown", "conflicting", "unsupported", "not_evaluated"]
Freshness = Literal["fresh", "stale", "untested"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunIn(StrictModel):
    snapshot_id: uuid.UUID
    idempotency_key: str = Field(min_length=8, max_length=200, pattern=r"^[A-Za-z0-9_.:-]{8,200}$")


def _fail(exc: GraphFailure) -> HTTPException:
    if exc.code == "source_rejected":
        return HTTPException(status_code=404, detail=_NOT_FOUND)
    if exc.code == "kill_switch":
        return HTTPException(status_code=503, detail="kill_switch")
    if exc.code in {"cancelled", "publication_race"}:
        return HTTPException(status_code=409, detail=exc.code)
    return HTTPException(status_code=422, detail=exc.code)


def _stamp(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _run(row: AnalysisRun) -> dict:
    return {
        "id": str(row.id),
        "snapshot_id": str(row.snapshot_id),
        "ruleset_version": row.ruleset_version,
        "identity": row.identity,
        "status": row.status,
        "is_current": row.is_current,
        "content_hash": row.content_hash,
        "started_at": _stamp(row.started_at),
        "completed_at": _stamp(row.completed_at),
        "result_count": row.result_count,
        "limitations": row.limitations,
        "supersedes_id": str(row.supersedes_id) if row.supersedes_id else None,
    }


def _result(row: AnalysisResult) -> dict:
    return {
        "id": str(row.id),
        "run_id": str(row.run_id),
        "snapshot_id": str(row.snapshot_id),
        "category": row.category,
        "state": row.state,
        "rule_id": row.rule_id,
        "rule_version": row.rule_version,
        "service_key": plain_text(row.service_key or ""),
        "explanation": plain_text(row.explanation),
        "evidence_modes": row.evidence_modes,
        "maturity": row.maturity,
        "freshness": row.freshness,
        "limitations": row.limitations,
        "missing_facts": [plain_text(str(item)) for item in row.missing_facts],
        "node_keys": [plain_text(str(item)) for item in row.node_keys],
        "edge_keys": [plain_text(str(item)) for item in row.edge_keys],
    }


def _completed(db, workspace, run_id: uuid.UUID) -> AnalysisRun:
    row = db.scalar(select(AnalysisRun).where(
        AnalysisRun.id == run_id,
        AnalysisRun.tenant_id == workspace.tenant_id,
        AnalysisRun.workspace_id == workspace.id,
        AnalysisRun.status == "completed",
    ))
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


def _current(db, workspace) -> AnalysisRun:
    row = db.scalar(select(AnalysisRun).where(
        AnalysisRun.tenant_id == workspace.tenant_id,
        AnalysisRun.workspace_id == workspace.id,
        AnalysisRun.status == "completed",
        AnalysisRun.is_current.is_(True),
    ))
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


@router.post("/runs", status_code=201)
def start_run(payload: RunIn, workspace: WorkspaceScope, db: DbSession) -> dict:
    if workspace.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    try:
        row = execute(
            db,
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
            snapshot_id=payload.snapshot_id,
            actor=workspace.subject,
            idempotency_key=payload.idempotency_key,
        )
    except GraphFailure as exc:
        raise _fail(exc) from None
    return _run(row)


@router.get("/runs")
def list_runs(workspace: WorkspaceScope, db: DbSession, limit: Limit = 50, offset: Offset = 0) -> list[dict]:
    rows = db.scalars(select(AnalysisRun).where(
        AnalysisRun.tenant_id == workspace.tenant_id,
        AnalysisRun.workspace_id == workspace.id,
        AnalysisRun.status.in_(("completed", "failed", "cancelled")),
    ).order_by(AnalysisRun.created_at.desc(), AnalysisRun.id).limit(limit).offset(offset))
    return [_run(row) for row in rows]


@router.get("/current")
def current_run(workspace: WorkspaceScope, db: DbSession) -> dict:
    return _run(_current(db, workspace))


@router.get("/rules")
def list_rules(workspace: WorkspaceScope) -> dict:
    _ = workspace
    return {
        "ruleset_version": RULESET_VERSION,
        "categories": list(CATEGORIES),
        "states": list(STATES),
        "limitations": list(GLOBAL_LIMITATIONS),
        "bounds": {
            "max_depth": MAX_DEPTH,
            "max_fanout": MAX_FANOUT,
            "max_paths": MAX_PATHS,
            "max_inspected": MAX_INSPECTED,
            "max_seconds": MAX_SECONDS,
        },
        "rules": list(RULES),
    }


@router.get("/results")
def list_results(
    workspace: WorkspaceScope,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    run_id: uuid.UUID | None = None,
    category: Category | None = None,
    state: State | None = None,
    freshness: Freshness | None = None,
    service_id: uuid.UUID | None = None,
) -> list[dict]:
    run = _completed(db, workspace, run_id) if run_id else _current(db, workspace)
    query = select(AnalysisResult).where(
        AnalysisResult.run_id == run.id,
        AnalysisResult.tenant_id == workspace.tenant_id,
        AnalysisResult.workspace_id == workspace.id,
        AnalysisResult.snapshot_id == run.snapshot_id,
    )
    if category:
        query = query.where(AnalysisResult.category == category)
    if state:
        query = query.where(AnalysisResult.state == state)
    if freshness:
        query = query.where(AnalysisResult.freshness == freshness)
    if service_id:
        service = db.scalar(select(GraphNode).where(
            GraphNode.id == service_id,
            GraphNode.snapshot_id == run.snapshot_id,
            GraphNode.tenant_id == workspace.tenant_id,
            GraphNode.workspace_id == workspace.id,
        ))
        if service is None:
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        query = query.where(AnalysisResult.service_key == service.source_key)
    rows = db.scalars(query.order_by(AnalysisResult.category, AnalysisResult.rule_id, AnalysisResult.id).limit(limit).offset(offset))
    return [_result(row) for row in rows]


@router.get("/results/{result_id}")
def get_result(result_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = db.scalar(select(AnalysisResult).where(
        AnalysisResult.id == result_id,
        AnalysisResult.tenant_id == workspace.tenant_id,
        AnalysisResult.workspace_id == workspace.id,
    ))
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    run = _completed(db, workspace, row.run_id)
    if row.snapshot_id != run.snapshot_id:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return _result(row)


@router.get("/gaps")
def list_gaps(
    workspace: WorkspaceScope,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    run_id: uuid.UUID | None = None,
) -> list[dict]:
    run = _completed(db, workspace, run_id) if run_id else _current(db, workspace)
    rows = db.scalars(select(AnalysisResult).where(
        AnalysisResult.run_id == run.id,
        AnalysisResult.tenant_id == workspace.tenant_id,
        AnalysisResult.workspace_id == workspace.id,
        or_(
            AnalysisResult.category == "contradiction_gap",
            AnalysisResult.state.in_(("unknown", "conflicting", "unsupported")),
        ),
    ).order_by(AnalysisResult.category, AnalysisResult.rule_id, AnalysisResult.id).limit(limit).offset(offset))
    return [_result(row) for row in rows]
