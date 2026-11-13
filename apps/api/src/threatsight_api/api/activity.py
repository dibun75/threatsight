"""Read-only observed-activity view. Collection from external feeds is not implemented."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from threatsight_api.activity.project import DIRECTIONS, LAYERS, WINDOWS, activity_view

router = APIRouter(prefix="/activity", tags=["activity"])


@router.get("/summary")
def summary(
    window: str = Query(default="24h"),
    layer: str = Query(default="all"),
    direction: str = Query(default="target"),
) -> dict:
    if window not in WINDOWS or layer not in LAYERS or direction not in DIRECTIONS:
        raise HTTPException(status_code=400, detail="Unsupported activity query")
    return activity_view(window=window, layer=layer, direction=direction)
