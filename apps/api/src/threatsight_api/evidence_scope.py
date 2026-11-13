"""Service evidence is limited to explicit workspace links. Display names are not relationships."""

from __future__ import annotations

import uuid

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session


def service_evidence_ids(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, service_id: uuid.UUID) -> list[uuid.UUID]:
    source_key = db.execute(
        text(
            """
            SELECT node.source_key
            FROM graph_nodes AS node
            JOIN graph_snapshots AS snapshot ON snapshot.id = node.snapshot_id
            WHERE node.id = :service
              AND node.tenant_id = :tenant
              AND node.workspace_id = :workspace
              AND node.node_type = 'business_service'
              AND snapshot.is_current
            """
        ),
        {"service": service_id, "tenant": tenant_id, "workspace": workspace_id},
    ).scalar()
    if source_key is None:
        raise HTTPException(status_code=404, detail="Service not found")
    rows = db.execute(
        text(
            """
            SELECT evidence_id
            FROM reference_evidence_links
            WHERE workspace_id = :workspace AND service_source_key = :source_key
            ORDER BY evidence_key
            """
        ),
        {"workspace": workspace_id, "source_key": source_key},
    )
    return [row[0] for row in rows]
