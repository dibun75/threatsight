"""Load the current workspace snapshot and project service decisions."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.decisions.project import project_one, summarize
from threatsight_api.investigations.reference import CHAINS
from threatsight_api.graph.sanitize import plain_text
from threatsight_api.persistence.models import (
    AnalysisResult,
    AnalysisRun,
    CorrelationMatch,
    CorrelationRun,
    GraphNode,
    GraphServiceMembership,
    GraphSnapshot,
    LandscapeAdvisory,
)


def services(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID) -> dict:
    snapshot = _snapshot(db, tenant_id, workspace_id)
    if snapshot is None:
        return summarize([])
    rows = list(
        db.scalars(
            select(GraphNode)
            .where(
                GraphNode.snapshot_id == snapshot.id,
                GraphNode.tenant_id == tenant_id,
                GraphNode.workspace_id == workspace_id,
                GraphNode.node_type == "business_service",
            )
            .order_by(GraphNode.source_key)
            .limit(20)
        )
    )
    memberships = list(
        db.scalars(
            select(GraphServiceMembership).where(
                GraphServiceMembership.snapshot_id == snapshot.id,
                GraphServiceMembership.tenant_id == tenant_id,
                GraphServiceMembership.workspace_id == workspace_id,
            )
        )
    )
    member_ids = {item.member_node_id for item in memberships}
    member_nodes = {}
    if member_ids:
        member_nodes = {
            node.id: node
            for node in db.scalars(
                select(GraphNode).where(
                    GraphNode.id.in_(member_ids),
                    GraphNode.snapshot_id == snapshot.id,
                )
            )
        }
    matches = _matches(db, tenant_id, workspace_id, snapshot.id)
    advisories = _advisories(db)
    results = _results(db, tenant_id, workspace_id, snapshot.id)
    controls = _reference_controls(db, workspace_id)
    by_service = {item["service"]: item for item in CHAINS}
    projected = []
    for row in rows:
        members = []
        for item in memberships:
            if item.service_node_id != row.id:
                continue
            member = member_nodes.get(item.member_node_id)
            if member is None:
                continue
            members.append(
                {
                    "source_key": member.source_key,
                    "label": plain_text(member.label),
                    "role": item.role,
                    "evidence_mode": item.evidence_mode,
                }
            )
        projected.append(
            project_one(
                service={
                    "id": str(row.id),
                    "label": plain_text(row.label),
                    "source_key": row.source_key,
                    "maturity": row.maturity,
                    "purpose": plain_text((row.attributes or {}).get("name") or row.label),
                },
                members=members,
                matches=_preferred(matches, by_service.get(row.source_key)),
                advisories=advisories,
                results=results,
                controls=controls,
                snapshot_current=bool(snapshot.is_current),
            )
        )
    return summarize(projected)


def one(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, service_id: uuid.UUID) -> dict | None:
    body = services(db, tenant_id, workspace_id)
    return next((item for item in body["services"] if item["service_id"] == str(service_id)), None)


def _reference_controls(db: Session, workspace_id: uuid.UUID) -> list[dict]:
    from sqlalchemy import text

    found = db.execute(
        text(
            """
            SELECT service_source_key, control_title, decision_text, evidence_status, owner_state
            FROM reference_journeys
            WHERE workspace_id = :workspace
            """
        ),
        {"workspace": workspace_id},
    ).mappings()
    return [
        {
            "service_key": row["service_source_key"],
            "title": row["control_title"],
            "decision": row["decision_text"],
            "evidence_status": row["evidence_status"],
            "owner_state": row["owner_state"],
        }
        for row in found
    ]


def _preferred(matches: list[dict], chain: dict | None) -> list[dict]:
    if chain is None:
        return matches
    asset = chain["asset"]

    def rank(item: dict) -> tuple[int, int]:
        key = str(item.get("asset_key") or "")
        return (item.get("cve") != chain["cve"], key != asset and key != f"{asset}:software")

    return sorted(matches, key=rank)


def _snapshot(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID) -> GraphSnapshot | None:
    return db.scalar(
        select(GraphSnapshot).where(
            GraphSnapshot.tenant_id == tenant_id,
            GraphSnapshot.workspace_id == workspace_id,
            GraphSnapshot.is_current.is_(True),
            GraphSnapshot.status == "completed",
        )
    )


def _matches(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, snapshot_id: uuid.UUID) -> list[dict]:
    run = db.scalar(
        select(CorrelationRun).where(
            CorrelationRun.tenant_id == tenant_id,
            CorrelationRun.workspace_id == workspace_id,
            CorrelationRun.is_current.is_(True),
            CorrelationRun.snapshot_id == snapshot_id,
        )
    )
    if run is None:
        return []
    rows = db.scalars(
        select(CorrelationMatch)
        .where(CorrelationMatch.run_id == run.id, CorrelationMatch.workspace_id == workspace_id)
        .order_by(CorrelationMatch.cve, CorrelationMatch.asset_key)
        .limit(200)
    )
    return [
        {
            "cve": row.cve,
            "state": row.state,
            "asset_key": plain_text(row.asset_key),
            "maturity": row.maturity,
            "freshness": row.freshness,
            "services": list(row.services or []),
            "epss_score": row.epss_score,
            "epss_date": row.epss_date,
        }
        for row in rows
    ]


def _advisories(db: Session) -> list[dict]:
    rows = db.scalars(select(LandscapeAdvisory).where(LandscapeAdvisory.withdrawn.is_(False)).limit(200))
    return [
        {
            "title": plain_text(row.title),
            "cves": list(row.cves or [])[:8],
            "maturity": row.maturity,
            "kev_listed": row.kev_listed,
            "epss_score": row.epss_score,
            "epss_date": None,
            "withdrawn": row.withdrawn,
        }
        for row in rows
    ]


def _results(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, snapshot_id: uuid.UUID) -> list[dict]:
    run = db.scalar(
        select(AnalysisRun).where(
            AnalysisRun.tenant_id == tenant_id,
            AnalysisRun.workspace_id == workspace_id,
            AnalysisRun.is_current.is_(True),
            AnalysisRun.snapshot_id == snapshot_id,
        )
    )
    if run is None:
        return []
    rows = db.scalars(
        select(AnalysisResult)
        .where(AnalysisResult.run_id == run.id, AnalysisResult.workspace_id == workspace_id)
        .order_by(AnalysisResult.category, AnalysisResult.id)
        .limit(100)
    )
    return [
        {
            "state": row.state,
            "freshness": row.freshness,
            "evidence_modes": list(row.evidence_modes or []),
            "explanation": plain_text(row.explanation),
            "node_keys": [plain_text(item) for item in list(row.node_keys or [])[:8]],
        }
        for row in rows
    ]

