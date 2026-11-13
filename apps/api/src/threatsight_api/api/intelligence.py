from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from threatsight_api.api.deps import Actor, DbSession, require_entity
from threatsight_api.api.schemas import IntelligenceExplainIn, IntelligenceTaskIn
from threatsight_api.config import get_settings
from threatsight_api.domain.intelligence import INTELLIGENCE_TASKS
from threatsight_api.intelligence.llm import IntelligenceMalformed
from threatsight_api.intelligence.service import explain_system, intelligence_status, run_task
from threatsight_api.persistence.models import AISystemRecord

router = APIRouter(prefix="/intelligence", tags=["intelligence"])


@router.get("/status")
def status() -> dict:
    return intelligence_status(get_settings())


@router.get("/explain")
def get_explain(system_id: uuid.UUID, db: DbSession) -> dict:
    system = require_entity(db, AISystemRecord, system_id, "AI system")
    return explain_system(db, get_settings(), system, actor="auditor", persist=False, use_llm=False)


@router.post("/explain")
def post_explain(body: IntelligenceExplainIn, db: DbSession, actor: Actor) -> dict:
    system = require_entity(db, AISystemRecord, body.system_id, "AI system")
    return explain_system(
        db,
        get_settings(),
        system,
        actor,
        persist=body.persist,
        use_llm=body.use_llm,
    )


@router.post("/tasks")
def post_task(body: IntelligenceTaskIn, db: DbSession, actor: Actor) -> dict:
    if body.task not in INTELLIGENCE_TASKS:
        raise HTTPException(status_code=400, detail="Unknown intelligence task")
    system = require_entity(db, AISystemRecord, body.system_id, "AI system") if body.system_id else None
    if body.task != "explain_posture" and system is None:
        raise HTTPException(status_code=400, detail="system_id is required")
    try:
        if body.task == "explain_posture":
            if system is None:
                raise HTTPException(status_code=400, detail="system_id is required")
            return explain_system(
                db,
                get_settings(),
                system,
                actor,
                persist=body.persist,
                use_llm=body.use_llm,
            )
        return run_task(db, get_settings(), actor, task=body.task, system=system, persist=body.persist)
    except IntelligenceMalformed as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
