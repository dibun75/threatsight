"""Persisted telemetry reads. The API process does not collect or see the Radar token."""

from __future__ import annotations

from fastapi import APIRouter

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.telemetry.read import activity as read_activity
from threatsight_api.observatory.read import abusech_observations
from threatsight_api.observatory.read import observations as read_observations
from threatsight_api.observatory.read import (
    threatfox_observations as read_threatfox_observations,
)

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("/activity")
def activity(db: DbSession, scope: WorkspaceScope) -> dict:
    del scope
    return read_activity(db)


@router.get("/observations")
def observations(db: DbSession, scope: WorkspaceScope, limit: int = 100) -> dict:
    del scope
    return read_observations(db, limit=limit)


@router.get("/observations/threatfox")
def threatfox_observations(
    db: DbSession, scope: WorkspaceScope, limit: int = 50
) -> dict:
    del scope
    return read_threatfox_observations(db, limit=limit)


@router.get("/observations/feodo")
def feodo_observations(db: DbSession, scope: WorkspaceScope, limit: int = 100) -> dict:
    del scope
    return abusech_observations(db, "feodo", limit=limit)


@router.get("/observations/urlhaus")
def urlhaus_observations(db: DbSession, scope: WorkspaceScope, limit: int = 100) -> dict:
    del scope
    return abusech_observations(db, "urlhaus", limit=limit)
