"""Workspace-scoped graph reads. Depth is one. There is no path language."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select

from threatsight_api.api.deps import DbSession, Limit, Offset, WorkspaceScope
from threatsight_api.graph.bounds import MAX_NEIGHBORS
from threatsight_api.graph.materialize import add_membership, materialize
from threatsight_api.graph.sanitize import GraphFailure, plain_payload, plain_text
from threatsight_api.graph.vocabulary import EDGE_TYPES, MEMBER_ROLES, NODE_TYPES
from threatsight_api.persistence.models import (
    GraphConflict,
    GraphEdge,
    GraphNode,
    GraphObservation,
    GraphServiceMembership,
    GraphSnapshot,
)

router = APIRouter(prefix="/graph", tags=["graph"])
_NOT_FOUND = "Graph object not found"
ADMIN_ROLES = frozenset({"workspace-admin", "platform-admin"})


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BuildIn(StrictModel):
    idempotency_key: str = Field(min_length=8, max_length=200, pattern=r"^[A-Za-z0-9_.:-]{8,200}$")
    fixture: Literal["nordic-retail", "partial"] | None = None
    job_ids: list[uuid.UUID] = Field(default_factory=list, max_length=10)


class MembershipIn(StrictModel):
    member_node_id: uuid.UUID
    role: Literal["entry", "dependency", "identity", "network", "administration"]


def _fail(exc: GraphFailure) -> HTTPException:
    if exc.code == "source_rejected":
        return HTTPException(status_code=404, detail=_NOT_FOUND)
    if exc.code == "fixture_rejected":
        return HTTPException(status_code=422, detail=exc.code)
    if exc.code == "kill_switch":
        return HTTPException(status_code=503, detail="kill_switch")
    if exc.code in {"cancelled", "membership_exists", "publication_race"}:
        return HTTPException(status_code=409, detail=exc.code)
    return HTTPException(status_code=422, detail=exc.code)


def _stamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _snapshot(row: GraphSnapshot) -> dict:
    return {
        "id": str(row.id),
        "status": row.status,
        "is_current": row.is_current,
        "content_hash": row.content_hash,
        "source_fingerprint": row.source_fingerprint,
        "started_at": _stamp(row.started_at),
        "completed_at": _stamp(row.completed_at),
        "materialized_at": _stamp(row.materialized_at),
        "node_count": row.node_count,
        "edge_count": row.edge_count,
        "limitations": row.limitations,
        "supersedes_id": str(row.supersedes_id) if row.supersedes_id else None,
    }


def _node(row: GraphNode) -> dict:
    return {
        "id": str(row.id),
        "node_type": row.node_type,
        "source_key": plain_text(row.source_key),
        "vendor_id": plain_text(row.vendor_id),
        "label": plain_text(row.label),
        "maturity": row.maturity,
        "evidence_mode": row.evidence_mode,
        "connector_key": row.connector_key,
        "source_contract": row.source_contract,
        "source_record_id": row.source_record_id,
        "collected_at": _stamp(row.collected_at),
        "materialized_at": _stamp(row.materialized_at),
        "freshness": row.freshness,
        "confidence": row.confidence,
        "limitations": row.limitations,
        "lifecycle": row.lifecycle,
        "attributes": plain_payload(row.attributes),
    }


def _edge(row: GraphEdge) -> dict:
    return {
        "id": str(row.id),
        "edge_type": row.edge_type,
        "source_key": plain_text(row.source_key),
        "from_node_id": str(row.from_node_id),
        "to_node_id": str(row.to_node_id),
        "maturity": row.maturity,
        "evidence_mode": row.evidence_mode,
        "connector_key": row.connector_key,
        "source_contract": row.source_contract,
        "source_record_id": row.source_record_id,
        "collected_at": _stamp(row.collected_at),
        "materialized_at": _stamp(row.materialized_at),
        "freshness": row.freshness,
        "confidence": row.confidence,
        "limitations": row.limitations,
        "lifecycle": row.lifecycle,
        "derivation_rule": row.derivation_rule,
        "derivation_version": row.derivation_version,
        "contributing": plain_payload(row.contributing),
    }


def _completed(db, workspace, snapshot_id: uuid.UUID) -> GraphSnapshot:
    row = db.scalar(select(GraphSnapshot).where(
        GraphSnapshot.id == snapshot_id,
        GraphSnapshot.tenant_id == workspace.tenant_id,
        GraphSnapshot.workspace_id == workspace.id,
        GraphSnapshot.status == "completed",
    ))
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


def _current(db, workspace) -> GraphSnapshot:
    row = db.scalar(select(GraphSnapshot).where(
        GraphSnapshot.tenant_id == workspace.tenant_id,
        GraphSnapshot.workspace_id == workspace.id,
        GraphSnapshot.status == "completed",
        GraphSnapshot.is_current.is_(True),
    ))
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


@router.post("/builds", status_code=201)
def build_graph(payload: BuildIn, workspace: WorkspaceScope, db: DbSession) -> dict:
    if workspace.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    try:
        row = materialize(
            db,
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
            actor=workspace.subject,
            idempotency_key=payload.idempotency_key,
            fixture=payload.fixture,
            job_ids=payload.job_ids,
        )
    except GraphFailure as exc:
        raise _fail(exc) from None
    return _snapshot(row)


@router.get("/snapshots")
def list_snapshots(workspace: WorkspaceScope, db: DbSession, limit: Limit = 50, offset: Offset = 0) -> list[dict]:
    rows = db.scalars(select(GraphSnapshot).where(
        GraphSnapshot.tenant_id == workspace.tenant_id,
        GraphSnapshot.workspace_id == workspace.id,
        GraphSnapshot.status == "completed",
    ).order_by(GraphSnapshot.completed_at.desc(), GraphSnapshot.id).limit(limit).offset(offset))
    return [_snapshot(row) for row in rows]


@router.get("/snapshots/current")
def current_snapshot(workspace: WorkspaceScope, db: DbSession) -> dict:
    return _snapshot(_current(db, workspace))


@router.get("/snapshots/{snapshot_id}")
def get_snapshot(snapshot_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    return _snapshot(_completed(db, workspace, snapshot_id))


@router.get("/nodes")
def list_nodes(
    workspace: WorkspaceScope,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    snapshot_id: uuid.UUID | None = None,
    node_type: str | None = None,
) -> list[dict]:
    if node_type is not None and node_type not in NODE_TYPES:
        raise HTTPException(status_code=422, detail="vocabulary_rejected")
    snapshot = _completed(db, workspace, snapshot_id) if snapshot_id else _current(db, workspace)
    query = select(GraphNode).where(
        GraphNode.snapshot_id == snapshot.id,
        GraphNode.tenant_id == workspace.tenant_id,
        GraphNode.workspace_id == workspace.id,
    )
    if node_type:
        query = query.where(GraphNode.node_type == node_type)
    rows = db.scalars(query.order_by(GraphNode.node_type, GraphNode.source_key, GraphNode.id).limit(limit).offset(offset))
    return [_node(row) for row in rows]


@router.get("/edges")
def list_edges(
    workspace: WorkspaceScope,
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    snapshot_id: uuid.UUID | None = None,
    edge_type: str | None = None,
) -> list[dict]:
    if edge_type is not None and edge_type not in EDGE_TYPES:
        raise HTTPException(status_code=422, detail="vocabulary_rejected")
    snapshot = _completed(db, workspace, snapshot_id) if snapshot_id else _current(db, workspace)
    query = select(GraphEdge).where(
        GraphEdge.snapshot_id == snapshot.id,
        GraphEdge.tenant_id == workspace.tenant_id,
        GraphEdge.workspace_id == workspace.id,
    )
    if edge_type:
        query = query.where(GraphEdge.edge_type == edge_type)
    rows = db.scalars(query.order_by(GraphEdge.edge_type, GraphEdge.source_key, GraphEdge.id).limit(limit).offset(offset))
    return [_edge(row) for row in rows]


@router.get("/nodes/{node_id}")
def node_neighborhood(
    node_id: uuid.UUID,
    workspace: WorkspaceScope,
    db: DbSession,
    depth: int = Query(default=1, ge=1, le=1),
    limit: int = Query(default=MAX_NEIGHBORS, ge=1, le=MAX_NEIGHBORS),
) -> dict:
    _ = depth
    node = db.scalar(select(GraphNode).where(
        GraphNode.id == node_id,
        GraphNode.tenant_id == workspace.tenant_id,
        GraphNode.workspace_id == workspace.id,
    ))
    if node is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    snapshot = _completed(db, workspace, node.snapshot_id)
    edges = list(db.scalars(select(GraphEdge).where(
        GraphEdge.snapshot_id == snapshot.id,
        GraphEdge.tenant_id == workspace.tenant_id,
        GraphEdge.workspace_id == workspace.id,
        or_(GraphEdge.from_node_id == node.id, GraphEdge.to_node_id == node.id),
    ).order_by(GraphEdge.edge_type, GraphEdge.source_key, GraphEdge.id).limit(limit + 1)))
    truncated = len(edges) > limit
    edges = edges[:limit]
    neighbor_ids = {edge.from_node_id for edge in edges} | {edge.to_node_id for edge in edges}
    neighbor_ids.discard(node.id)
    neighbors = []
    if neighbor_ids:
        neighbors = list(db.scalars(select(GraphNode).where(
            GraphNode.id.in_(neighbor_ids),
            GraphNode.snapshot_id == snapshot.id,
            GraphNode.tenant_id == workspace.tenant_id,
            GraphNode.workspace_id == workspace.id,
        ).order_by(GraphNode.node_type, GraphNode.source_key)))
    limitations = ["neighborhood_depth_one", "not_an_exposure_finding"]
    if truncated:
        limitations.append("neighborhood_truncated")
    return {"node": _node(node), "edges": [_edge(edge) for edge in edges], "neighbors": [_node(item) for item in neighbors], "limitations": limitations}


@router.get("/services")
def list_services(workspace: WorkspaceScope, db: DbSession, limit: Limit = 50, offset: Offset = 0) -> list[dict]:
    snapshot = _current(db, workspace)
    rows = db.scalars(select(GraphNode).where(
        GraphNode.snapshot_id == snapshot.id,
        GraphNode.tenant_id == workspace.tenant_id,
        GraphNode.workspace_id == workspace.id,
        GraphNode.node_type == "business_service",
    ).order_by(GraphNode.source_key).limit(limit).offset(offset))
    return [_node(row) for row in rows]


@router.get("/services/{service_id}/members")
def list_members(service_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, limit: Limit = 50, offset: Offset = 0) -> dict:
    snapshot = _current(db, workspace)
    service = db.scalar(select(GraphNode).where(
        GraphNode.id == service_id,
        GraphNode.snapshot_id == snapshot.id,
        GraphNode.tenant_id == workspace.tenant_id,
        GraphNode.workspace_id == workspace.id,
        GraphNode.node_type == "business_service",
    ))
    if service is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    rows = db.scalars(select(GraphServiceMembership).where(
        GraphServiceMembership.snapshot_id == snapshot.id,
        GraphServiceMembership.service_node_id == service.id,
        GraphServiceMembership.tenant_id == workspace.tenant_id,
        GraphServiceMembership.workspace_id == workspace.id,
    ).order_by(GraphServiceMembership.role, GraphServiceMembership.member_node_id).limit(limit).offset(offset))
    members = [{
        "id": str(row.id),
        "member_node_id": str(row.member_node_id),
        "role": row.role,
        "evidence_mode": row.evidence_mode,
        "maturity": row.maturity,
        "limitations": row.limitations,
        "scoped_at": _stamp(row.scoped_at),
    } for row in rows]
    return {"service": _node(service), "members": members, "limitations": ["not_an_exposure_finding"]}


@router.get("/nodes/{node_id}/provenance")
def node_provenance(node_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, limit: Limit = 50) -> dict:
    node = db.scalar(select(GraphNode).where(
        GraphNode.id == node_id,
        GraphNode.tenant_id == workspace.tenant_id,
        GraphNode.workspace_id == workspace.id,
    ))
    if node is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    _completed(db, workspace, node.snapshot_id)
    observations = db.scalars(select(GraphObservation).where(
        GraphObservation.snapshot_id == node.snapshot_id,
        GraphObservation.subject_key == node.source_key,
        GraphObservation.tenant_id == workspace.tenant_id,
        GraphObservation.workspace_id == workspace.id,
    ).order_by(GraphObservation.collected_at, GraphObservation.id).limit(limit))
    conflicts = db.scalars(select(GraphConflict).where(
        GraphConflict.snapshot_id == node.snapshot_id,
        GraphConflict.subject_key == node.source_key,
        GraphConflict.tenant_id == workspace.tenant_id,
        GraphConflict.workspace_id == workspace.id,
    ).order_by(GraphConflict.conflict_type, GraphConflict.detail_code).limit(limit))
    return {
        "node": _node(node),
        "observations": [{
            "connector_key": item.connector_key,
            "source_contract": item.source_contract,
            "source_record_id": item.source_record_id,
            "evidence_mode": item.evidence_mode,
            "maturity": item.maturity,
            "collected_at": _stamp(item.collected_at),
            "materialized_at": _stamp(item.materialized_at),
            "payload": plain_payload(item.payload),
        } for item in observations],
        "conflicts": [{
            "conflict_type": item.conflict_type,
            "detail_code": item.detail_code,
            "limitations": item.limitations,
        } for item in conflicts],
    }


@router.post("/services/{service_id}/members", status_code=201)
def create_membership(service_id: uuid.UUID, payload: MembershipIn, workspace: WorkspaceScope, db: DbSession) -> dict:
    if workspace.role not in ADMIN_ROLES or payload.role not in MEMBER_ROLES:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    try:
        row = add_membership(
            db,
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
            actor=workspace.subject,
            service_node_id=service_id,
            member_node_id=payload.member_node_id,
            role=payload.role,
        )
    except GraphFailure as exc:
        raise _fail(exc) from None
    return {
        "id": str(row.id),
        "member_node_id": str(row.member_node_id),
        "role": row.role,
        "evidence_mode": row.evidence_mode,
        "maturity": row.maturity,
        "limitations": row.limitations,
    }
