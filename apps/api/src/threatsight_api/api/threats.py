from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from threatsight_api.api.deps import Actor, DbSession, require_entity
from threatsight_api.api.schemas import ControlOut
from threatsight_api.persistence.models import ControlRecord, IntelAdvisory, IntelAdvisoryTechnique, IntelTechnique, IntelThreat
from threatsight_api.services.dashboard import findings_to_out
from threatsight_api.services.identity import identity_for
from threatsight_api.services.operations import threat_landscape
from threatsight_api.threats.catalog import CATALOG_VERSION, threat_for
from threatsight_api.threats.engine import (
    bootstrap_intel,
    ingest_advisory,
    intel_totals,
    load_technique_impact,
    load_threat_summary,
    map_technique_control,
)
from threatsight_api.threats.ingest import IntelIngestError

router = APIRouter(prefix="/threats", tags=["threats"])


class TechniqueMapCreate(BaseModel):
    control_id: uuid.UUID
    note: str | None = None


def _advisory_out(db, record: IntelAdvisory) -> dict:
    links = list(db.scalars(select(IntelAdvisoryTechnique).where(IntelAdvisoryTechnique.advisory_id == record.id)))
    techniques = []
    for link in links:
        technique = db.get(IntelTechnique, link.technique_id)
        if technique is not None:
            threat = db.get(IntelThreat, technique.threat_id)
            techniques.append(
                {
                    "key": technique.key,
                    "title": technique.title,
                    "threat_key": threat.key if threat else None,
                }
            )
    return {
        "id": str(record.id),
        "key": record.key,
        "title": record.title,
        "summary": record.summary,
        "locator": record.locator,
        "source_kind": record.source_kind,
        "catalog_version": record.catalog_version,
        "ingested_by": record.ingested_by,
        "informational_only": bool(record.informational_only),
        "legal_compliance_claim": False,
        "techniques": techniques,
    }


def _technique_card(technique: IntelTechnique, impact: dict) -> dict:
    return {
        "id": str(technique.id),
        "key": technique.key,
        "title": technique.title,
        "statement": technique.statement,
        "locator": technique.locator,
        "source_kind": technique.source_kind,
        "catalog_version": technique.catalog_version,
        "framework_key": technique.framework_key,
        "reference_code": technique.reference_code,
        "affected_capability": technique.affected_capability,
        "informational_only": bool(technique.informational_only),
        "mapped": impact["mapped"],
        "coverage_status": impact["coverage_status"],
        "control_count": len(impact["controls"]),
        "suggested_test_count": len(impact["suggested_tests"]),
        "legal_compliance_claim": False,
    }


@router.post("/demo/bootstrap")
def bootstrap(db: DbSession, actor: Actor) -> dict:
    return bootstrap_intel(db, actor)


@router.post("/ingest")
def ingest(body: dict, db: DbSession, actor: Actor) -> dict:
    try:
        record = ingest_advisory(db, actor, body)
    except IntelIngestError as exc:
        detail = str(exc)
        status = 409 if "already exists" in detail else 400
        raise HTTPException(status_code=status, detail=detail) from exc
    return {
        "id": str(record.id),
        "key": record.key,
        "title": record.title,
        "locator": record.locator,
        "source_kind": record.source_kind,
        "catalog_version": record.catalog_version,
        "informational_only": True,
        "legal_compliance_claim": False,
        "unrestricted_crawl": False,
        "news_mutates_assurance": False,
    }


@router.get("/status")
def threat_status(db: DbSession) -> dict:
    totals = intel_totals(db)
    return {
        **totals,
        "llm_is_intel_authority": False,
        "autonomous_attack": False,
        "exploitation_engine": False,
        "unrestricted_crawl": False,
        "news_mutates_assurance": False,
        "legal_compliance_claim": False,
        "catalog_complete": False,
        "catalog_version": CATALOG_VERSION,
    }


@router.get("/advisories")
def list_advisories(db: DbSession) -> list[dict]:
    rows = list(db.scalars(select(IntelAdvisory).order_by(IntelAdvisory.key)))
    return [_advisory_out(db, item) for item in rows]


@router.get("/advisories/{advisory_key}")
def get_advisory(advisory_key: str, db: DbSession) -> dict:
    record = db.scalar(select(IntelAdvisory).where(IntelAdvisory.key == advisory_key))
    if record is None:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return _advisory_out(db, record)


@router.get("")
def list_threats(db: DbSession) -> list[dict]:
    rows = list(db.scalars(select(IntelThreat).order_by(IntelThreat.key)))
    states = {item["key"]: item["evidence_state"] for item in threat_landscape(db)}
    return [
        {
            "id": item["id"],
            "key": item["key"],
            "title": item["title"],
            "statement": item["statement"],
            "technique_count": item["technique_count"],
            "mapped_techniques": item["mapped_techniques"],
            "evidence_state": states.get(item["key"], "not_assessed"),
            "catalog_version": item["catalog_version"],
            "catalog_complete": False,
            "legal_compliance_claim": False,
            "informational_only": True,
        }
        for item in (load_threat_summary(db, row) for row in rows)
    ]


@router.get("/{threat_key}")
def get_threat(threat_key: str, db: DbSession) -> dict:
    if threat_for(threat_key) is None:
        raise HTTPException(status_code=404, detail="Unknown threat")
    record = db.scalar(select(IntelThreat).where(IntelThreat.key == threat_key))
    if record is None:
        raise HTTPException(status_code=404, detail="Threat not found")
    summary = load_threat_summary(db, record)
    states = {item["key"]: item["evidence_state"] for item in threat_landscape(db)}
    return {
        **{k: v for k, v in summary.items() if k != "items"},
        "evidence_state": states.get(record.key, "not_assessed"),
        "techniques": [_technique_card(technique, impact) for technique, impact in summary["items"]],
    }


@router.get("/{threat_key}/techniques/{technique_key}")
def get_technique(threat_key: str, technique_key: str, db: DbSession) -> dict:
    if threat_for(threat_key) is None:
        raise HTTPException(status_code=404, detail="Unknown threat")
    technique = db.scalar(select(IntelTechnique).where(IntelTechnique.key == technique_key))
    if technique is None:
        raise HTTPException(status_code=404, detail="Technique not found")
    threat = db.get(IntelThreat, technique.threat_id)
    if threat is None or threat.key != threat_key:
        raise HTTPException(status_code=404, detail="Technique not found")
    impact = load_technique_impact(db, technique)
    framework = impact["framework_reference"]
    return {
        **_technique_card(technique, impact),
        "threat_key": threat.key,
        "threat_title": threat.title,
        "catalog_complete": False,
        "controls": [ControlOut.model_validate(item) for item in impact["controls"]],
        "systems": [
            {
                "id": str(item.id),
                "name": item.name,
                "display_name": identity_for(item)["display_name"],
                "environment": item.environment,
                "owner": item.owner,
            }
            for item in impact["systems"]
        ],
        "findings": findings_to_out(db, impact["findings"]),
        "suggested_tests": [
            {
                "scenario_key": item.scenario_key,
                "rationale": item.rationale,
                "executes": False,
            }
            for item in impact["suggested_tests"]
        ],
        "framework_reference": (
            {
                "id": str(framework.id),
                "framework_key": framework.framework_key,
                "reference_code": framework.reference_code,
                "locator": framework.locator,
            }
            if framework is not None
            else None
        ),
        "legal_compliance_claim": False,
    }


@router.post("/{threat_key}/techniques/{technique_key}/control-mappings", status_code=201)
def map_control(
    threat_key: str,
    technique_key: str,
    body: TechniqueMapCreate,
    db: DbSession,
    actor: Actor,
) -> dict:
    technique = db.scalar(select(IntelTechnique).where(IntelTechnique.key == technique_key))
    if technique is None:
        raise HTTPException(status_code=404, detail="Technique not found")
    threat = db.get(IntelThreat, technique.threat_id)
    if threat is None or threat.key != threat_key:
        raise HTTPException(status_code=404, detail="Technique not found")
    control = require_entity(db, ControlRecord, body.control_id, "Control")
    try:
        link = map_technique_control(db, technique, control, actor, body.note)
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Technique mapping already exists") from exc
    return {
        "id": str(link.id),
        "technique_key": technique.key,
        "control_id": str(control.id),
        "note": link.note,
        "informational_only": True,
        "legal_compliance_claim": False,
    }
