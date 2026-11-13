from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from pydantic import Field

from threatsight_api.api.deps import Actor, DbSession, Limit, require_entity
from threatsight_api.api.schemas import StrictModel
from threatsight_api.connectivity.contract import SOURCE_KINDS, ConnectivityIngestError
from threatsight_api.connectivity.ingest import event_to_dict, ingest_event, list_events
from threatsight_api.persistence.models import AISystemRecord

router = APIRouter(prefix="/connectivity", tags=["connectivity"])


class AgentEventIn(StrictModel):
    ai_system_id: uuid.UUID
    source_kind: str = Field(min_length=3, max_length=32)
    agent_id: str | None = Field(default=None, max_length=200)
    session_id: str | None = Field(default=None, max_length=200)
    user_context: str | None = Field(default=None, max_length=500)
    tool_name: str | None = Field(default=None, max_length=200)
    arguments: dict = Field(default_factory=dict)
    authorization_context: dict = Field(default_factory=dict)
    result_metadata: dict = Field(default_factory=dict)
    occurred_at: datetime | None = None
    correlation_id: str | None = Field(default=None, max_length=128)
    labelled_synthetic: bool = False


@router.get("/status")
def connectivity_status() -> dict:
    return {
        "source_kinds": sorted(SOURCE_KINDS),
        "passive_ingest": True,
        "runtime_firewall": False,
        "autonomous_attack": False,
        "legal_compliance_claim": False,
        "enforcement": "none",
    }


@router.post("/events", status_code=201)
def create_event(body: AgentEventIn, db: DbSession, actor: Actor) -> dict:
    try:
        event = ingest_event(db, actor, body.model_dump())
    except ConnectivityIngestError as exc:
        detail = str(exc)
        status = 404 if "not found" in detail.lower() else 400
        raise HTTPException(status_code=status, detail=detail) from exc
    return event_to_dict(event)


@router.get("/events")
def get_events(
    db: DbSession,
    system_id: uuid.UUID | None = Query(default=None),
    limit: Limit = 50,
) -> list[dict]:
    if system_id is not None:
        require_entity(db, AISystemRecord, system_id, "AI system")
    return [event_to_dict(item) for item in list_events(db, system_id, limit=limit)]
