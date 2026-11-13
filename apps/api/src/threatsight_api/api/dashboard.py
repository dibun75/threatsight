from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from threatsight_api.api.deps import DbSession
from threatsight_api.api.schemas import DashboardFinding, DashboardOut, DashboardRun
from threatsight_api.persistence.models import AISystemRecord, ControlRecord
from threatsight_api.services.dashboard import build_dashboard
from threatsight_api.services.identity import identity_for

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardOut)
def get_dashboard(
    db: DbSession,
    scope: str | None = Query(default=None, description="showcase, all, or omit for auto"),
) -> DashboardOut:
    if scope not in {None, "showcase", "all"}:
        raise HTTPException(status_code=400, detail="scope must be showcase or all")
    raw = build_dashboard(db, scope=scope)
    systems = {item.id: item for item in db.scalars(select(AISystemRecord))}
    control_ids = {item.id: item.identifier for item in db.scalars(select(ControlRecord))}
    counts = raw.get("high_risk_duplicate_counts") or [1] * len(raw["high_risk_findings"])
    high = []
    for item, duplicate_count in zip(raw["high_risk_findings"], counts, strict=False):
        system = systems.get(item.ai_system_id)
        ident = identity_for(system) if system is not None else None
        high.append(
            DashboardFinding(
                id=item.id,
                title=item.title,
                severity=item.severity,
                status=item.status,
                verdict=item.verdict,
                ai_system_id=item.ai_system_id,
                control_id=item.control_id,
                evidence_id=item.evidence_id,
                ai_system_name=system.name if system is not None else None,
                ai_system_display_name=ident["display_name"] if ident else None,
                control_identifier=control_ids.get(item.control_id),
                duplicate_count=int(duplicate_count),
            )
        )
    runs = [
        DashboardRun(
            id=item.id,
            scenario_key=item.scenario_key,
            verdict=item.verdict,
            reason_code=item.reason_code,
            control_id=item.control_id,
            finding_id=item.finding_id,
            evidence_id=item.evidence_id,
            parent_run_id=item.parent_run_id,
            finished_at=item.finished_at,
        )
        for item in raw["recent_runs"]
    ]
    return DashboardOut(
        legal_compliance_claim=False,
        synthetic_demo_labelled=True,
        synthetic_demo_present=raw["synthetic_demo_present"],
        scope=raw.get("scope") or "all",
        scope_reason=raw.get("scope_reason") or "all_records",
        llm_available=bool(raw.get("llm_available")),
        intelligence_provider=str(raw.get("intelligence_provider") or "heuristic"),
        systems=raw["systems"],
        controls=raw["controls"],
        findings=raw["findings"],
        evidence=raw["evidence"],
        documents=raw["documents"],
        discovery=raw["discovery"],
        frameworks=raw["frameworks"],
        threats=raw["threats"],
        high_risk_findings=high,
        recent_runs=runs,
        recent_activity=raw.get("recent_activity") or [],
        evidence_freshness=raw["evidence_freshness"],
        executive_summary=raw["executive_summary"],
        operations=raw.get("operations") or {},
    )
