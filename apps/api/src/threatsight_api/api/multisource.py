"""Emerging exploitation intelligence APIs."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.multisource import service as multisource_service

router = APIRouter(prefix="/multisource", tags=["multisource"])


@router.get("/clusters")
def clusters(
    db: DbSession,
    scope: WorkspaceScope,
    limit: int = Query(default=50, ge=1, le=100),
) -> dict:
    del scope
    return multisource_service.list_clusters(db, limit=limit)


@router.get("/clusters/{cluster_id}")
def cluster(cluster_id: uuid.UUID, db: DbSession, scope: WorkspaceScope) -> dict:
    del scope
    return multisource_service.cluster_detail(db, cluster_id)


@router.get("/sources")
def sources(db: DbSession, scope: WorkspaceScope) -> dict:
    del scope
    return multisource_service.source_health(db)


@router.get("/command-center")
def command_center(db: DbSession, scope: WorkspaceScope) -> dict:
    """Material exploitation changes with organization relevance only."""
    del scope
    page = multisource_service.list_clusters(db, limit=25)
    items = []
    for item in page["items"]:
        relevance = item.get("organization_relevance")
        if not relevance or "No stored organization" in str(relevance) or "No strong-identifier" in str(relevance):
            continue
        if item.get("exploitation_state") in {"not_reported", "unknown"} and "Warehouse" not in str(relevance):
            # Still show warehouse synthetic journey when product match exists.
            if "Synthetic product" not in str(relevance):
                continue
        items.append(
            {
                "cluster_id": item["id"],
                "cve": item.get("cve"),
                "title": item["title"],
                "exploitation_state": item["exploitation_state"],
                "organization_relevance": relevance,
                "required_action": "Manual verification recommendation (approval required)",
            }
        )
    return {
        "items": items,
        "note": "Command Center shows material exploitation changes only when organization technology relevance exists. General news is excluded.",
    }
