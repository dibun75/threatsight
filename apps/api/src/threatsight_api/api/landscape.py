from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.landscape import read as landscape_read

router = APIRouter(prefix="/landscape", tags=["landscape"])


@router.get("/summary")
def summary(db: DbSession, scope: WorkspaceScope) -> dict:
    del scope
    return landscape_read.summary(db)


@router.get("/sources")
def sources(db: DbSession, scope: WorkspaceScope) -> dict:
    del scope
    return landscape_read.sources(db)


@router.get("/advisories")
def advisories(
    db: DbSession,
    scope: WorkspaceScope,
    limit: int = Query(default=25, ge=1, le=50),
) -> dict:
    return landscape_read.advisories(db, scope.id, limit)


@router.get("/advisories/{advisory_id}")
def advisory(advisory_id: uuid.UUID, db: DbSession, scope: WorkspaceScope) -> dict:
    found = landscape_read.advisory(db, scope.id, advisory_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return found


@router.get("/countries")
def countries(scope: WorkspaceScope) -> dict:
    from threatsight_api.landscape.countries import ORGANIZATION_COUNTRIES, country_rows

    del scope
    return {"countries": country_rows(), "organization": list(ORGANIZATION_COUNTRIES)}


@router.get("/geography")
def geography(
    db: DbSession,
    scope: WorkspaceScope,
    metric: str = Query(default="authority_jurisdiction", max_length=40),
) -> dict:
    del scope
    return landscape_read.geography(db, metric)


@router.get("/matrix")
def matrix(db: DbSession, scope: WorkspaceScope) -> dict:
    del scope
    return landscape_read.matrix(db)


@router.get("/catalog")
def catalog(db: DbSession, scope: WorkspaceScope) -> dict:
    del scope
    return landscape_read.catalog(db)
