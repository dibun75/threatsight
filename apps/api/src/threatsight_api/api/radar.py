from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy import select

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.persistence.models import (
    OrganizationProfile,
    ThreatSource,
)
from threatsight_api.radar.contracts import (
    ManualThreatEventIn,
    OrganizationProfileIn,
    RadarFilterSchema,
)
from threatsight_api.radar.query import query_events
from threatsight_api.radar.service import import_manual_event, recompute_relevance, sync_source

router = APIRouter(prefix="/radar", tags=["radar"])
WRITE_ROLES = {"operator", "workspace-admin", "platform-admin"}


def _require_workspace_write(scope: WorkspaceScope) -> None:
    if scope.role not in WRITE_ROLES:
        raise HTTPException(status_code=403, detail="Workspace role is read-only")


def _profile_out(profile: OrganizationProfile, workspace_key: str) -> dict:
    return {
        "workspace": workspace_key,
        "countries": profile.countries,
        "sectors": profile.sectors,
        "vendors": profile.vendors,
        "products": profile.products,
        "technologies": profile.technologies,
        "critical_services": profile.critical_services,
        "minimum_relevance": profile.minimum_relevance,
        "updated_at": profile.updated_at,
    }


@router.get("/workspace")
def workspace_context(scope: WorkspaceScope) -> dict:
    return {
        "key": scope.key,
        "subject": scope.subject,
        "role": scope.role,
        "isolation": "membership_enforced",
        "legacy_tables_tenant_scoped": False,
    }


@router.get("/sources")
def list_sources(db: DbSession, scope: WorkspaceScope) -> list[dict]:
    rows = list(db.scalars(select(ThreatSource).order_by(ThreatSource.key)))
    return [
        {
            "key": item.key,
            "provider": item.provider,
            "authority": item.authority,
            "country": item.country,
            "locator": item.locator,
            "format": item.source_format,
            "sync_mode": item.sync_mode,
            "polling_minutes": item.polling_minutes,
            "jurisdiction": item.jurisdiction,
            "license_url": item.license_url,
            "storage_policy": item.storage_policy,
            "attribution": item.attribution,
            "parser_version": item.parser_version,
            "enabled": item.enabled,
            "last_synced_at": item.last_synced_at,
            "last_success_at": item.last_success_at,
            "last_status": item.last_status,
            "last_error": item.last_error,
            "consecutive_failures": item.consecutive_failures,
            "workspace": scope.key,
        }
        for item in rows
    ]


@router.post("/sources/{source_key}/sync")
def run_source_sync(source_key: str, db: DbSession, scope: WorkspaceScope):
    _require_workspace_write(scope)
    result = sync_source(db, source_key)
    result["workspace"] = scope.key
    if result["status"] != "ok":
        return JSONResponse(result, status_code=502)
    return result


@router.post("/sources/{source_key}/events")
def create_manual_source_event(
    source_key: str,
    body: ManualThreatEventIn,
    db: DbSession,
    scope: WorkspaceScope,
) -> dict:
    _require_workspace_write(scope)
    try:
        result = import_manual_event(db, source_key, body, scope.subject)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {**result, "workspace": scope.key}


@router.get("/profile")
def get_profile(db: DbSession, scope: WorkspaceScope) -> dict:
    profile = db.scalar(select(OrganizationProfile).where(OrganizationProfile.workspace_id == scope.id))
    if profile is None:
        raise HTTPException(status_code=404, detail="Organization profile not found")
    return _profile_out(profile, scope.key)


@router.put("/profile")
def update_profile(body: OrganizationProfileIn, db: DbSession, scope: WorkspaceScope) -> dict:
    _require_workspace_write(scope)
    profile = db.scalar(select(OrganizationProfile).where(OrganizationProfile.workspace_id == scope.id))
    if profile is None:
        profile = OrganizationProfile(workspace_id=scope.id)
        db.add(profile)
    for field, value in body.model_dump().items():
        setattr(profile, field, value)
    db.flush()
    recompute_relevance(db)
    return _profile_out(profile, scope.key)


@router.get("/events")
def list_events(
    db: DbSession,
    scope: WorkspaceScope,
    country: str | None = Query(default=None, min_length=2, max_length=2),
    geography: Literal["any", "authority", "target", "victim", "infrastructure", "prevalence"] = "any",
    sector: str | None = Query(default=None, max_length=100),
    vendor: str | None = Query(default=None, max_length=100),
    product: str | None = Query(default=None, max_length=200),
    technology: str | None = Query(default=None, max_length=100),
    event_type: Literal["advisory", "vulnerability", "campaign", "incident_report", "national_risk_level_change"] | None = None,
    source: str | None = Query(default=None, max_length=64),
    published_after: datetime | None = None,
    published_before: datetime | None = None,
    minimum_relevance: int | None = Query(default=None, ge=0, le=100),
    relevance: Literal["none", "low", "medium", "high", "critical"] | None = None,
    exploitation_status: Literal["unknown", "not_observed", "suspected", "proof_of_concept", "known_exploited"] | None = None,
    sort: Literal["published_at", "updated_at", "relevance"] = "published_at",
    direction: Literal["asc", "desc"] = "desc",
    page: int = Query(default=1, ge=1, le=1000),
    limit: int = Query(default=50, ge=1, le=100),
) -> dict:
    profile = db.scalar(select(OrganizationProfile).where(OrganizationProfile.workspace_id == scope.id))
    filters = RadarFilterSchema(
        country=country,
        geography=geography,
        sector=sector,
        vendor=vendor,
        product=product,
        technology=technology,
        event_type=event_type,
        source=source,
        published_after=published_after,
        published_before=published_before,
        minimum_relevance=minimum_relevance,
        relevance=relevance,
        exploitation_status=exploitation_status,
        sort=sort,
        direction=direction,
        page=page,
        limit=limit,
    )
    result = query_events(db, scope.id, filters, profile.minimum_relevance if profile else 0)
    items = []
    for event, origin, event_relevance in result["rows"]:
        signals = [
            signal
            for cve in event.cves
            for signal in result["signals"].get(cve, [])
        ]
        triage = result["triage"].get(event.id)
        items.append(
            {
                "id": str(event.id),
                "external_id": event.external_id,
                "event_type": event.event_type,
                "title": event.title,
                "summary": event.summary,
                "canonical_url": event.canonical_url,
                "published_at": event.published_at,
                "source_updated_at": event.source_updated_at,
                "ingested_at": event.ingested_at,
                "content_hash": event.content_hash,
                "confidence": event.confidence,
                "countries": event.countries,
                "geography": {
                    "authority_jurisdictions": event.authority_jurisdictions,
                    "target_countries": event.target_countries,
                    "victim_countries": event.victim_countries,
                    "infrastructure_countries": event.infrastructure_countries,
                    "prevalence_countries": event.prevalence_countries,
                },
                "sectors": event.sectors,
                "vendors": event.vendors,
                "products": event.products,
                "technologies": event.technologies,
                "cves": event.cves,
                "exploitation_status": event.exploitation_status,
                "parser_version": event.parser_version,
                "provenance": event.provenance,
                "limitations": event.limitations,
                "attributes": event.attributes,
                "source": {
                    "key": origin.key,
                    "provider": origin.provider,
                    "authority": origin.authority,
                    "locator": origin.locator,
                    "jurisdiction": origin.jurisdiction,
                    "license_url": origin.license_url,
                    "storage_policy": origin.storage_policy,
                    "attribution": origin.attribution,
                },
                "relevance": {
                    "score": event_relevance.score,
                    "level": event_relevance.level,
                    "reasons": event_relevance.reasons,
                    "matches": event_relevance.matches,
                    "assessed_at": event_relevance.assessed_at,
                },
                "clusters": result["clusters"].get(event.id, []),
                "triage": (
                    {
                        "status": triage.status,
                        "priority": triage.priority,
                        "owner": triage.owner,
                        "due_at": triage.due_at,
                        "rationale": triage.rationale,
                        "updated_at": triage.updated_at,
                    }
                    if triage
                    else None
                ),
                "readiness_links": [
                    {
                        "id": str(link.id),
                        "target_type": link.target_type,
                        "target_id": str(link.target_id),
                        "reason": link.reason,
                        "provenance": link.provenance,
                        "limitations": link.limitations,
                    }
                    for link in result["links"].get(event.id, [])
                ],
                "epss": [
                    {
                        "cve": signal.cve,
                        "score": signal.epss_score,
                        "percentile": signal.percentile,
                        "score_date": signal.score_date,
                    }
                    for signal in signals
                ],
                "informational_only": True,
                "exposure_confirmed": False,
                "legal_compliance_claim": False,
            }
        )
    return {
        "workspace": scope.key,
        "minimum_relevance": result["threshold"],
        "page": page,
        "limit": limit,
        "total": result["total"],
        "count": len(items),
        "items": items,
        "limitations": [
            "Relevance is profile correlation, not proof of asset exposure.",
            "Geography is source-provided relevance, not attacker attribution.",
            "Events do not change assurance verdicts automatically.",
        ],
    }
