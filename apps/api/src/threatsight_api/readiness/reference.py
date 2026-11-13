"""Idempotent Phase 3A readiness reference rows."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from threatsight_api.readiness.engine import recommend_for_workspace


def install(connection) -> None:
    """Create readiness recommendations for current synthetic journeys. Safe to rerun."""
    session = Session(bind=connection)
    try:
        workspaces = session.execute(
            __import__("sqlalchemy").text(
                """
                SELECT DISTINCT tenant_id, workspace_id
                FROM graph_snapshots
                WHERE is_current
                """
            )
        ).mappings()
        for row in workspaces:
            recommend_for_workspace(
                session,
                uuid.UUID(str(row["tenant_id"])),
                uuid.UUID(str(row["workspace_id"])),
                actor="migration:0025",
            )
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
