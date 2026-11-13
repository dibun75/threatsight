"""Workspace-scoped investigation reads. Relationships come from stored keys."""

from __future__ import annotations

import uuid

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from threatsight_api.decisions.read import one
from threatsight_api.graph.sanitize import plain_text
from threatsight_api.investigations.project import classification, evidence_state, path_steps
from threatsight_api.presentation import public_name
from threatsight_api.persistence.models import (
    AnalysisResult,
    AnalysisRun,
    CorrelationMatch,
    CorrelationRun,
    GraphEdge,
    GraphNode,
    GraphServiceMembership,
    GraphSnapshot,
    LandscapeAdvisory,
)

_LIMITS = [
    "not_packet_delivery",
    "not_compromise",
    "not_control_effectiveness",
    "absence_is_not_safety",
]


def service(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, service_id: uuid.UUID) -> dict | None:
    decision = one(db, tenant_id, workspace_id, service_id)
    if decision is None:
        return None
    snapshot = _snapshot(db, tenant_id, workspace_id)
    if snapshot is None:
        return None
    node = db.get(GraphNode, service_id)
    if node is None or node.snapshot_id != snapshot.id or node.workspace_id != workspace_id:
        return None
    assets = _assets(db, snapshot, node)
    threats = _threats(db, tenant_id, workspace_id, snapshot, node.source_key, assets)
    paths = _paths(db, tenant_id, workspace_id, snapshot, node, assets)
    controls = _policies(paths, assets)
    journey = _journey(db, workspace_id, node.source_key)
    if journey is not None:
        controls = [journey["control"], *controls][:10]
    stamps = [item["collected_at"] for item in assets if item["collected_at"]]
    stamps.extend(item["collected_at"] for item in threats if item["collected_at"])
    return {
        "service_id": str(node.id),
        "name": plain_text(node.label),
        "source_key": plain_text(node.source_key),
        "purpose": decision["purpose"],
        "maturity": node.maturity,
        "data_context": "Live public advisory intelligence" if node.maturity == "live_verified" else "Synthetic enterprise evidence",
        "decision_state": decision["state"],
        "explanation": decision["explanation"],
        "recommended_step": journey["decision_text"] if journey else decision["recommended_step"],
        "owner_state": journey["owner_state"] if journey else "not_assigned",
        "deadline_state": journey["deadline_state"] if journey else "not_recorded",
        "consequence": journey["consequence"] if journey else None,
        "evidence_completeness": (
            f"Recorded members {len(assets)}. Recorded matches {len(threats)}. Recorded paths {len(paths)}. Control evidence {journey['evidence_status']}."
            if journey
            else f"Recorded members {len(assets)}. Recorded matches {len(threats)}. Recorded paths {len(paths)}. Linked assurance controls 0."
        ),
        "last_relevant_update": max(stamps) if stamps else None,
        "comparison": "Comparison unavailable.",
        "score": None,
        "threats": threats,
        "assets": assets,
        "paths": paths,
        "controls": controls,
        "actions": [journey["action"]] if journey else [],
        "journey": journey,
        "limitations": [*decision["limitations"], *_LIMITS],
        "provenance": {
            "snapshot_id": str(snapshot.id),
            "snapshot_completed_at": snapshot.completed_at.isoformat() if snapshot.completed_at else None,
            "correlation_run_id": _run_id(db, CorrelationRun, tenant_id, workspace_id),
            "analysis_run_id": _run_id(db, AnalysisRun, tenant_id, workspace_id),
        },
    }


def _journey(db: Session, workspace_id: uuid.UUID, source_key: str) -> dict | None:
    row = db.execute(
        text(
            """
            SELECT id::text, consequence, decision_text, control_title, evidence_status, action_title,
                   owner_state, deadline_state, maturity, edge_id::text, match_id::text
            FROM reference_journeys
            WHERE workspace_id = :workspace AND service_source_key = :source
            """
        ),
        {"workspace": workspace_id, "source": source_key},
    ).mappings().first()
    if row is None:
        return None
    return {
        "id": row["id"],
        "maturity": row["maturity"],
        "consequence": row["consequence"],
        "decision_text": row["decision_text"],
        "owner_state": row["owner_state"],
        "deadline_state": row["deadline_state"],
        "evidence_status": row["evidence_status"],
        "edge_id": row["edge_id"],
        "match_id": row["match_id"],
        "control": {
            "id": row["id"],
            "kind": "reference_control",
            "title": row["control_title"],
            "objective": "Confirm the recorded evidence named by this synthetic journey.",
            "relevance": "The control is stored on this synthetic reference journey. Configuration is not observed effectiveness.",
            "expected_protection": "Not recorded",
            "latest_evidence": row["evidence_status"],
            "evidence_source": "Synthetic reference",
            "evidence_status": row["evidence_status"],
            "verification_maturity": row["maturity"],
            "gaps": ["owner_not_assigned"],
            "next_step": row["decision_text"],
        },
        "action": {
            "id": row["id"],
            "title": row["action_title"],
            "owner_state": row["owner_state"],
            "deadline_state": row["deadline_state"],
            "evidence_required": "Installed product version and an assigned owner.",
            "maturity": row["maturity"],
        },
    }


def path(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, result_id: uuid.UUID) -> dict | None:
    row = db.scalar(
        select(AnalysisResult).where(
            AnalysisResult.id == result_id,
            AnalysisResult.tenant_id == tenant_id,
            AnalysisResult.workspace_id == workspace_id,
        )
    )
    if row is None:
        return None
    snapshot = db.get(GraphSnapshot, row.snapshot_id)
    if snapshot is None or snapshot.workspace_id != workspace_id:
        return None
    service_node = None
    if row.service_key:
        service_node = db.scalar(
            select(GraphNode).where(
                GraphNode.snapshot_id == snapshot.id,
                GraphNode.workspace_id == workspace_id,
                GraphNode.source_key == row.service_key,
                GraphNode.node_type == "business_service",
            )
        )
    edges = _edges(db, snapshot, list(row.edge_keys or []))
    return {
        "id": str(row.id),
        "service_id": str(service_node.id) if service_node else None,
        "service_name": plain_text(service_node.label) if service_node else None,
        "state": row.state,
        "evidence_state": evidence_state(row.state if row.state in {"unknown", "conflicting", "unsupported"} else (row.evidence_modes[0] if row.evidence_modes else "unknown")),
        "freshness": row.freshness,
        "maturity": row.maturity,
        "source": row.rule_id,
        "explanation": plain_text(row.explanation),
        "collected_at": row.created_at.isoformat(),
        "steps": path_steps(list(row.edge_keys or []), edges),
        "limitations": list(row.limitations or []) + ["not_packet_delivery", "not_effective_reachability"],
    }


def _snapshot(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID) -> GraphSnapshot | None:
    return db.scalar(
        select(GraphSnapshot).where(
            GraphSnapshot.tenant_id == tenant_id,
            GraphSnapshot.workspace_id == workspace_id,
            GraphSnapshot.is_current.is_(True),
            GraphSnapshot.status == "completed",
        )
    )


def _assets(db: Session, snapshot: GraphSnapshot, service: GraphNode) -> list[dict]:
    rows = db.scalars(
        select(GraphServiceMembership).where(
            GraphServiceMembership.snapshot_id == snapshot.id,
            GraphServiceMembership.service_node_id == service.id,
            GraphServiceMembership.workspace_id == snapshot.workspace_id,
        ).limit(20)
    )
    items = []
    for row in rows:
        member = db.get(GraphNode, row.member_node_id)
        if member is None or member.snapshot_id != snapshot.id:
            continue
        items.append(_node(member, relationship="service_membership", role=row.role, mode=row.evidence_mode))
    return items


def _threats(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, snapshot: GraphSnapshot, source_key: str, assets: list[dict]) -> list[dict]:
    run = db.scalar(
        select(CorrelationRun).where(
            CorrelationRun.tenant_id == tenant_id,
            CorrelationRun.workspace_id == workspace_id,
            CorrelationRun.snapshot_id == snapshot.id,
            CorrelationRun.is_current.is_(True),
            CorrelationRun.status == "completed",
        )
    )
    if run is None:
        return []
    rows = db.scalars(
        select(CorrelationMatch).where(
            CorrelationMatch.run_id == run.id,
            CorrelationMatch.workspace_id == workspace_id,
        ).order_by(CorrelationMatch.cve, CorrelationMatch.id).limit(200)
    )
    by_cve = _advisories(db)
    by_asset = {item["source_key"]: item["node_id"] for item in assets}
    found = []
    for row in rows:
        named = next((item for item in row.services or [] if item.get("source_key") == source_key), None)
        if named is None:
            continue
        advisories = by_cve.get(row.cve, [])
        primary = next((item for item in advisories if item["maturity"] == "live_verified"), None) or (advisories[0] if advisories else None)
        found.append(
            {
                "match_id": str(row.id),
                "advisory_id": primary["id"] if primary else None,
                "additional_advisories": max(0, len(advisories) - (1 if primary else 0)),
                "cve": row.cve,
                "title": primary["title"] if primary else row.cve,
                "classification": classification(row.state),
                "state": row.state,
                "maturity": primary["maturity"] if primary else row.maturity,
                "freshness": row.freshness,
                "relationship": named.get("evidence_mode") or "unknown",
                "source": ",".join(str(item) for item in (row.sources or [])[:4]) or row.rule_id,
                "collected_at": row.created_at.isoformat(),
                "asset_key": plain_text(row.asset_key),
                "asset_node_id": by_asset.get(row.asset_key),
                "kev_listed": bool(primary["kev_listed"]) if primary else None,
                "epss_score": primary["epss_score"] if primary else row.epss_score,
                "epss_date": row.epss_date,
                "review_state": "stored separately",
                "limitations": list(row.limitations or [])[:8],
            }
        )
        if len(found) == 20:
            break
    return found


def _paths(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, snapshot: GraphSnapshot, service: GraphNode, assets: list[dict]) -> list[dict]:
    run = db.scalar(
        select(AnalysisRun).where(
            AnalysisRun.tenant_id == tenant_id,
            AnalysisRun.workspace_id == workspace_id,
            AnalysisRun.snapshot_id == snapshot.id,
            AnalysisRun.is_current.is_(True),
            AnalysisRun.status == "completed",
        )
    )
    if run is None:
        return []
    keys = {service.source_key} | {item["source_key"] for item in assets}
    rows = db.scalars(
        select(AnalysisResult).where(
            AnalysisResult.run_id == run.id,
            AnalysisResult.workspace_id == workspace_id,
        ).order_by(AnalysisResult.category, AnalysisResult.id).limit(100)
    )
    items = []
    for row in rows:
        if row.service_key != service.source_key and not keys.intersection(set(row.node_keys or [])):
            continue
        edges = _edges(db, snapshot, list(row.edge_keys or []))
        nodes = _nodes_for_keys(db, snapshot, list(row.node_keys or []))
        items.append(
            {
                "id": str(row.id),
                "state": row.state,
                "evidence_state": evidence_state(row.state if row.state in {"unknown", "conflicting", "unsupported"} else ((row.evidence_modes or ["unknown"])[0])),
                "freshness": row.freshness,
                "maturity": row.maturity,
                "source": row.rule_id,
                "explanation": plain_text(row.explanation),
                "collected_at": row.created_at.isoformat(),
                "steps": path_steps(list(row.edge_keys or []), edges),
                "nodes": nodes,
                "limitations": list(row.limitations or [])[:8],
            }
        )
        if len(items) == 10:
            break
    return items


def _policies(paths: list[dict], assets: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for asset in [*assets, *[node for item in paths for node in item["nodes"]]]:
        if asset["node_type"] == "security_policy":
            seen[asset["node_id"]] = asset
    controls = []
    for asset in seen.values():
        controls.append(
            {
                "id": asset["node_id"],
                "kind": "graph_security_policy",
                "title": asset["label"],
                "objective": "Stored security-policy graph record. Configuration is not control effectiveness.",
                "relevance": "The record key appears on a candidate path or service membership.",
                "expected_protection": "Not recorded",
                "latest_evidence": asset["evidence_state"],
                "evidence_source": asset["source"],
                "evidence_status": asset["freshness"],
                "verification_maturity": asset["maturity"],
                "gaps": asset["limitations"],
                "next_step": "Link an assurance control before treating this record as a verification.",
            }
        )
    return controls[:10]


def _edges(db: Session, snapshot: GraphSnapshot, keys: list[str]) -> dict[str, dict]:
    wanted = [item for item in keys if item][:12]
    if not wanted:
        return {}
    rows = db.scalars(
        select(GraphEdge).where(
            GraphEdge.snapshot_id == snapshot.id,
            GraphEdge.workspace_id == snapshot.workspace_id,
            GraphEdge.source_key.in_(wanted),
        )
    )
    nodes = {}
    edges = {}
    for row in rows:
        for node_id in (row.from_node_id, row.to_node_id):
            if node_id not in nodes:
                nodes[node_id] = db.get(GraphNode, node_id)
        edges[row.source_key] = {
            "id": str(row.id),
            "edge_type": row.edge_type,
            "from_label": plain_text(nodes[row.from_node_id].label) if nodes.get(row.from_node_id) else "Not recorded",
            "to_label": plain_text(nodes[row.to_node_id].label) if nodes.get(row.to_node_id) else "Not recorded",
            "evidence_mode": row.evidence_mode,
            "source": row.connector_key,
            "freshness": row.freshness,
            "collected_at": row.collected_at.isoformat(),
            "maturity": row.maturity,
            "confidence": row.confidence,
        }
    return edges


def _nodes_for_keys(db: Session, snapshot: GraphSnapshot, keys: list[str]) -> list[dict]:
    wanted = [item for item in keys if item][:12]
    if not wanted:
        return []
    rows = db.scalars(
        select(GraphNode).where(
            GraphNode.snapshot_id == snapshot.id,
            GraphNode.workspace_id == snapshot.workspace_id,
            GraphNode.source_key.in_(wanted),
        )
    )
    return [_node(row, relationship="path_node", role="path", mode=row.evidence_mode) for row in rows]


def _node(row: GraphNode, *, relationship: str, role: str, mode: str) -> dict:
    return {
        "node_id": str(row.id),
        "node_type": row.node_type,
        "label": public_name(row.source_key, plain_text(row.label)),
        "source_key": plain_text(row.source_key),
        "relationship": relationship,
        "role": role,
        "evidence_state": evidence_state(mode),
        "maturity": row.maturity,
        "freshness": row.freshness,
        "source": row.connector_key,
        "collected_at": row.collected_at.isoformat() if row.collected_at else None,
        "confidence": row.confidence,
        "limitations": list(row.limitations or [])[:6],
    }


def _advisories(db: Session) -> dict[str, list[dict]]:
    rows = db.scalars(select(LandscapeAdvisory).where(LandscapeAdvisory.withdrawn.is_(False)).limit(200))
    found: dict[str, list[dict]] = {}
    for row in rows:
        item = {"id": str(row.id), "title": plain_text(row.title), "maturity": row.maturity, "kev_listed": row.kev_listed, "epss_score": row.epss_score}
        for cve in row.cves or []:
            found.setdefault(str(cve), []).append(item)
    return found


def _run_id(db: Session, model, tenant_id: uuid.UUID, workspace_id: uuid.UUID) -> str | None:
    row = db.scalar(
        select(model).where(
            model.tenant_id == tenant_id,
            model.workspace_id == workspace_id,
            model.is_current.is_(True),
            model.status == "completed",
        )
    )
    return str(row.id) if row else None
