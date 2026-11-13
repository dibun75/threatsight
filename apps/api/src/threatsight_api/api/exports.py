from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse

from threatsight_api.api.deps import DbSession
from threatsight_api.services.exports import (
    audit_csv,
    control_matrix_csv,
    export_audit,
    export_control_matrix,
    export_controls,
    export_evidence,
    export_findings,
    export_grc_bundle,
    findings_csv,
)

router = APIRouter(prefix="/exports", tags=["exports"])
Limit = Query(ge=1, le=1000, default=200)


@router.get("/findings.json")
def findings_json(db: DbSession, limit: int = Limit) -> dict:
    return export_findings(db, limit)


@router.get("/findings.csv")
def findings_csv_out(db: DbSession, limit: int = Limit) -> PlainTextResponse:
    payload = export_findings(db, limit)
    return PlainTextResponse(findings_csv(payload), media_type="text/csv")


@router.get("/evidence.json")
def evidence_json(db: DbSession, limit: int = Limit) -> dict:
    return export_evidence(db, limit)


@router.get("/controls.json")
def controls_json(db: DbSession, limit: int = Limit) -> dict:
    return export_controls(db, limit)


@router.get("/audit.json")
def audit_json(db: DbSession, limit: int = Limit) -> dict:
    return export_audit(db, limit)


@router.get("/audit.csv")
def audit_csv_out(db: DbSession, limit: int = Limit) -> PlainTextResponse:
    payload = export_audit(db, limit)
    return PlainTextResponse(audit_csv(payload), media_type="text/csv")


@router.get("/grc-bundle.json")
def grc_bundle(db: DbSession, limit: int = Limit) -> dict:
    return export_grc_bundle(db, limit)


@router.get("/control-matrix.json")
def control_matrix_json(
    db: DbSession,
    limit: int = Limit,
    scope: Annotated[str | None, Query(max_length=16)] = None,
) -> dict:
    return export_control_matrix(db, limit, scope=scope)


@router.get("/control-matrix.csv")
def control_matrix_csv_out(
    db: DbSession,
    limit: int = Limit,
    scope: Annotated[str | None, Query(max_length=16)] = None,
) -> PlainTextResponse:
    payload = export_control_matrix(db, limit, scope=scope)
    return PlainTextResponse(control_matrix_csv(payload), media_type="text/csv")
