from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, require_entity
from threatsight_api.api.schemas import FindingOut, RemediationOut, RunCreate, RunOut
from threatsight_api.assurance.catalog import CATALOG
from threatsight_api.assurance.engine import (
    AssuranceEngineError,
    bootstrap_demo,
    execute_run,
    get_adapter,
    remediate,
)
from threatsight_api.assurance.safety import AssuranceSafetyError
from threatsight_api.config import get_settings
from threatsight_api.domain.invariants import DETERMINISTIC_EVALUATOR
from threatsight_api.persistence.models import AssuranceRunRecord, FindingRecord, RemediationRecord
from threatsight_api.services.dashboard import findings_to_out
from threatsight_api.services.scope import resolve_list_scope

router = APIRouter(prefix="/assurance", tags=["assurance"])
findings_router = APIRouter(prefix="/findings", tags=["findings"])


def _engine_http(exc: AssuranceEngineError | AssuranceSafetyError):
    raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post("/demo/bootstrap")
def bootstrap(db: DbSession, actor: Actor) -> dict:
    settings = get_settings()
    try:
        return bootstrap_demo(db, settings, actor)
    except AssuranceEngineError as exc:
        _engine_http(exc)
    except AssuranceSafetyError as exc:
        _engine_http(exc)


@router.get("/status")
def assurance_status(db: DbSession) -> dict:
    settings = get_settings()
    adapter = get_adapter(settings)
    try:
        state = adapter.state()
    except Exception as exc:
        state = {"error": str(exc)}
    return {
        "execution_engine": "ctrl002_tool_authorization",
        "adapter": settings.assurance_adapter,
        "demo_agent_url": settings.demo_agent_url,
        "kill_switch": settings.kill_switch,
        "sandbox_default": settings.sandbox_default,
        "llm_is_verdict_authority": False,
        "evaluator": DETERMINISTIC_EVALUATOR,
        "scenarios": [
            {"key": item.key, "title": item.title, "kind": item.kind} for item in CATALOG.values()
        ],
        "agent": state,
        "legal_compliance_claim": False,
    }


@router.post("/runs", status_code=201, response_model=RunOut)
def create_run(body: RunCreate, db: DbSession, actor: Actor) -> RunOut:
    settings = get_settings()
    try:
        run = execute_run(
            db,
            settings,
            scenario_key=body.scenario_key,
            actor=actor,
            confirm_execution=body.confirm_execution,
            parent_run_id=body.parent_run_id,
        )
    except (AssuranceEngineError, AssuranceSafetyError) as exc:
        _engine_http(exc)
    return _run_out(run)


@router.get("/runs", response_model=list[RunOut])
def list_runs(
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    control_id: uuid.UUID | None = None,
    verdict: Annotated[str | None, Query(max_length=32)] = None,
    scenario_key: Annotated[str | None, Query(max_length=32)] = None,
) -> list[RunOut]:
    stmt = select(AssuranceRunRecord)
    if control_id:
        stmt = stmt.where(AssuranceRunRecord.control_id == control_id)
    if verdict:
        stmt = stmt.where(AssuranceRunRecord.verdict == verdict)
    if scenario_key:
        stmt = stmt.where(AssuranceRunRecord.scenario_key == scenario_key)
    rows = list(db.scalars(stmt.order_by(AssuranceRunRecord.started_at.desc()).offset(offset).limit(limit)))
    return [_run_out(item) for item in rows]


@router.get("/runs/{run_id}", response_model=RunOut)
def get_run(run_id: uuid.UUID, db: DbSession) -> RunOut:
    run = require_entity(db, AssuranceRunRecord, run_id, "Assurance run")
    return _run_out(run)


@findings_router.get("", response_model=list[FindingOut])
def list_findings(
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    status: Annotated[str | None, Query(max_length=32)] = None,
    severity: Annotated[str | None, Query(max_length=32)] = None,
    control_id: uuid.UUID | None = None,
    ai_system_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    scope: Annotated[str | None, Query(max_length=16)] = None,
) -> list[FindingOut]:
    stmt = select(FindingRecord)
    _, system_ids = resolve_list_scope(db, scope)
    if system_ids is not None:
        if not system_ids:
            return []
        stmt = stmt.where(FindingRecord.ai_system_id.in_(system_ids))
    if status:
        stmt = stmt.where(FindingRecord.status == status)
    if severity:
        stmt = stmt.where(FindingRecord.severity == severity)
    if control_id:
        stmt = stmt.where(FindingRecord.control_id == control_id)
    if ai_system_id:
        stmt = stmt.where(FindingRecord.ai_system_id == ai_system_id)
    if evidence_id:
        stmt = stmt.where(FindingRecord.evidence_id == evidence_id)
    rows = list(db.scalars(stmt.order_by(FindingRecord.created_at.desc()).offset(offset).limit(limit)))
    return findings_to_out(db, rows)


@findings_router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: uuid.UUID, db: DbSession) -> FindingOut:
    finding = require_entity(db, FindingRecord, finding_id, "Finding")
    return findings_to_out(db, [finding])[0]


@findings_router.post("/{finding_id}/remediate", status_code=201, response_model=RemediationOut)
def remediate_finding(finding_id: uuid.UUID, db: DbSession, actor: Actor) -> RemediationOut:
    settings = get_settings()
    try:
        record = remediate(db, settings, finding_id, actor)
    except (AssuranceEngineError, AssuranceSafetyError) as exc:
        _engine_http(exc)
    return RemediationOut.model_validate(record)


@findings_router.get("/{finding_id}/remediations", response_model=list[RemediationOut])
def list_finding_remediations(finding_id: uuid.UUID, db: DbSession) -> list[RemediationOut]:
    require_entity(db, FindingRecord, finding_id, "Finding")
    rows = list(
        db.scalars(select(RemediationRecord).where(RemediationRecord.finding_id == finding_id).order_by(RemediationRecord.created_at))
    )
    return [RemediationOut.model_validate(item) for item in rows]


def _run_out(run: AssuranceRunRecord) -> RunOut:
    return RunOut(
        id=run.id,
        control_id=run.control_id,
        ai_system_id=run.ai_system_id,
        scenario_key=run.scenario_key,
        configuration=run.configuration or {},
        observation=run.observation or {},
        narration=run.narration,
        verdict=run.verdict,
        reason_code=run.reason_code,
        evidence_id=run.evidence_id,
        finding_id=run.finding_id,
        parent_run_id=run.parent_run_id,
        actor=run.actor,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )
