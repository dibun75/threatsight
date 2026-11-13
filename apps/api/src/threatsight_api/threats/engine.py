from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.assurance.catalog import CATALOG, CTRL_002
from threatsight_api.assurance.engine import DEMO_ENVIRONMENT, DEMO_SYSTEM_NAME
from threatsight_api.domain.enums import AuditAction
from threatsight_api.frameworks.coverage import coverage_from_control_statuses
from threatsight_api.persistence.models import (
    AISystemRecord,
    AssuranceRunRecord,
    ControlRecord,
    EvidenceControlLink,
    EvidenceSystemLink,
    FindingRecord,
    FrameworkReference,
    IntelAdvisory,
    IntelAdvisoryTechnique,
    IntelTechnique,
    IntelTechniqueControl,
    IntelTechniqueTest,
    IntelThreat,
)
from threatsight_api.services.audit import record_audit
from threatsight_api.threats.catalog import (
    ADVISORIES,
    CATALOG_VERSION,
    CTRL002_TECHNIQUES,
    CTRL002_TESTS,
    TECHNIQUES,
    THREATS,
    technique_for,
)
from threatsight_api.threats.ingest import AdvisoryIngest, IntelIngestError, parse_advisory


def sync_catalog(db: Session, actor: str = "system") -> dict[str, int]:
    threat_rows: dict[str, IntelThreat] = {}
    for item in THREATS:
        row = db.scalar(select(IntelThreat).where(IntelThreat.key == item.key))
        if row is None:
            row = IntelThreat(
                key=item.key,
                title=item.title[:200],
                statement=item.statement,
                catalog_version=CATALOG_VERSION,
                informational_only=True,
            )
            db.add(row)
            db.flush()
        else:
            row.title = item.title[:200]
            row.statement = item.statement
            row.catalog_version = CATALOG_VERSION
            row.informational_only = True
            db.flush()
        threat_rows[item.key] = row

    technique_count = 0
    for item in TECHNIQUES:
        threat = threat_rows[item.threat_key]
        row = db.scalar(select(IntelTechnique).where(IntelTechnique.key == item.key))
        if row is None:
            row = IntelTechnique(
                key=item.key,
                threat_id=threat.id,
                title=item.title[:200],
                statement=item.statement,
                locator=item.locator,
                source_kind=item.source_kind,
                catalog_version=CATALOG_VERSION,
                framework_key=item.framework_key,
                reference_code=item.reference_code,
                affected_capability=item.affected_capability,
                informational_only=True,
            )
            db.add(row)
            db.flush()
        else:
            row.threat_id = threat.id
            row.title = item.title[:200]
            row.statement = item.statement
            row.locator = item.locator
            row.source_kind = item.source_kind
            row.catalog_version = CATALOG_VERSION
            row.framework_key = item.framework_key
            row.reference_code = item.reference_code
            row.affected_capability = item.affected_capability
            row.informational_only = True
            db.flush()
        technique_count += 1

    for item in ADVISORIES:
        ingest_advisory(
            db,
            actor,
            AdvisoryIngest(
                key=item.key,
                title=item.title,
                summary=item.summary,
                locator=item.locator,
                source_kind=item.source_kind,
                technique_keys=list(item.technique_keys),
            ),
            catalog_seed=True,
        )
    return {"threats": len(threat_rows), "techniques": technique_count, "advisories": len(ADVISORIES)}


def ingest_advisory(
    db: Session,
    actor: str,
    payload: AdvisoryIngest | dict,
    *,
    catalog_seed: bool = False,
) -> IntelAdvisory:
    parsed = payload if isinstance(payload, AdvisoryIngest) else parse_advisory(payload)
    existing = db.scalar(select(IntelAdvisory).where(IntelAdvisory.key == parsed.key))
    created = existing is None
    if existing is None:
        existing = IntelAdvisory(
            key=parsed.key,
            title=parsed.title[:200],
            summary=parsed.summary,
            locator=parsed.locator,
            source_kind=parsed.source_kind,
            catalog_version=CATALOG_VERSION,
            ingested_by=actor,
            informational_only=True,
        )
        db.add(existing)
        db.flush()
    elif catalog_seed:
        existing.title = parsed.title[:200]
        existing.summary = parsed.summary
        existing.locator = parsed.locator
        existing.source_kind = parsed.source_kind
        existing.catalog_version = CATALOG_VERSION
        existing.informational_only = True
        db.flush()
    else:
        raise IntelIngestError("advisory key already exists")

    wanted = set(parsed.technique_keys)
    current = list(db.scalars(select(IntelAdvisoryTechnique).where(IntelAdvisoryTechnique.advisory_id == existing.id)))
    current_keys: dict[str, IntelAdvisoryTechnique] = {}
    for link in current:
        technique = db.get(IntelTechnique, link.technique_id)
        if technique is not None:
            current_keys[technique.key] = link
    for key, link in current_keys.items():
        if key not in wanted:
            db.delete(link)
    for key in parsed.technique_keys:
        if key in current_keys:
            continue
        technique = db.scalar(select(IntelTechnique).where(IntelTechnique.key == key))
        if technique is None:
            raise IntelIngestError(f"unknown technique_key: {key}")
        db.add(IntelAdvisoryTechnique(advisory_id=existing.id, technique_id=technique.id))
    db.flush()
    if created or not catalog_seed:
        record_audit(
            db,
            entity_type="intel_advisory",
            entity_id=existing.id,
            action=AuditAction.CREATE if created else AuditAction.UPDATE,
            actor=actor,
            payload={
                "key": existing.key,
                "locator": existing.locator,
                "source_kind": existing.source_kind,
                "catalog_seed": catalog_seed,
                "legal_compliance_claim": False,
                "unrestricted_crawl": False,
            },
        )
    return existing


def bootstrap_intel(db: Session, actor: str) -> dict:
    counts = sync_catalog(db, actor)
    control = db.scalar(select(ControlRecord).where(ControlRecord.identifier == CTRL_002))
    mapped: list[str] = []
    suggested: list[str] = []
    if control is not None:
        prior_status = control.assurance_status
        for key in CTRL002_TECHNIQUES:
            technique = db.scalar(select(IntelTechnique).where(IntelTechnique.key == key))
            if technique is None:
                continue
            existing = db.scalar(
                select(IntelTechniqueControl).where(
                    IntelTechniqueControl.technique_id == technique.id,
                    IntelTechniqueControl.control_id == control.id,
                )
            )
            if existing is None:
                db.add(
                    IntelTechniqueControl(
                        technique_id=technique.id,
                        control_id=control.id,
                        note="Informational M7 mapping for CTRL-002. Does not change assurance status.",
                    )
                )
                db.flush()
                record_audit(
                    db,
                    entity_type="control",
                    entity_id=control.id,
                    action=AuditAction.MAP,
                    actor=actor,
                    payload={
                        "technique_key": key,
                        "informational_only": True,
                        "legal_compliance_claim": False,
                        "source": "m7-bootstrap",
                    },
                )
            mapped.append(key)
        for item in CTRL002_TESTS:
            technique = db.scalar(select(IntelTechnique).where(IntelTechnique.key == item.technique_key))
            if technique is None:
                continue
            if item.scenario_key not in CATALOG:
                continue
            existing = db.scalar(
                select(IntelTechniqueTest).where(
                    IntelTechniqueTest.technique_id == technique.id,
                    IntelTechniqueTest.scenario_key == item.scenario_key,
                )
            )
            if existing is None:
                db.add(
                    IntelTechniqueTest(
                        technique_id=technique.id,
                        scenario_key=item.scenario_key,
                        rationale=item.rationale,
                    )
                )
                db.flush()
            suggested.append(f"{item.technique_key}:{item.scenario_key}")
        db.refresh(control)
        assert control.assurance_status == prior_status
    return {
        "catalog_version": CATALOG_VERSION,
        "catalog_complete": False,
        "legal_compliance_claim": False,
        "autonomous_attack": False,
        "exploitation_engine": False,
        "unrestricted_crawl": False,
        "news_mutates_assurance": False,
        "control_id": str(control.id) if control else None,
        "mapped_techniques": mapped,
        "suggested_tests": suggested,
        **counts,
    }


def map_technique_control(
    db: Session,
    technique: IntelTechnique,
    control: ControlRecord,
    actor: str,
    note: str | None,
) -> IntelTechniqueControl:
    prior = control.assurance_status
    link = IntelTechniqueControl(
        technique_id=technique.id,
        control_id=control.id,
        note=note or "Informational technique mapping. Does not change assurance status.",
    )
    db.add(link)
    db.flush()
    record_audit(
        db,
        entity_type="control",
        entity_id=control.id,
        action=AuditAction.MAP,
        actor=actor,
        payload={
            "technique_key": technique.key,
            "informational_only": True,
            "legal_compliance_claim": False,
        },
    )
    db.refresh(control)
    assert control.assurance_status == prior
    return link


def load_technique_impact(db: Session, technique: IntelTechnique) -> dict:
    links = list(db.scalars(select(IntelTechniqueControl).where(IntelTechniqueControl.technique_id == technique.id)))
    controls: list[ControlRecord] = []
    for link in links:
        control = db.get(ControlRecord, link.control_id)
        if control is not None:
            controls.append(control)
    statuses = [item.assurance_status for item in controls]
    tests = list(
        db.scalars(
            select(IntelTechniqueTest)
            .where(IntelTechniqueTest.technique_id == technique.id)
            .order_by(IntelTechniqueTest.scenario_key)
        )
    )
    control_ids = [item.id for item in controls]
    systems = systems_for_controls(db, control_ids)
    findings: list[FindingRecord] = []
    if control_ids:
        findings = list(
            db.scalars(
                select(FindingRecord)
                .where(FindingRecord.control_id.in_(control_ids), FindingRecord.status != "resolved")
                .order_by(FindingRecord.created_at.desc())
            )
        )
    framework = None
    spec = technique_for(technique.key)
    if spec and spec.framework_key and spec.reference_code:
        framework = db.scalar(
            select(FrameworkReference).where(
                FrameworkReference.framework_key == spec.framework_key,
                FrameworkReference.reference_code == spec.reference_code,
            )
        )
    return {
        "mapped": bool(controls),
        "coverage_status": coverage_from_control_statuses(statuses),
        "controls": controls,
        "systems": systems,
        "findings": findings[:20],
        "suggested_tests": tests,
        "framework_reference": framework,
        "legal_compliance_claim": False,
        "informational_only": True,
        "catalog_complete": False,
    }


def systems_for_controls(db: Session, control_ids: list) -> list[AISystemRecord]:
    if not control_ids:
        return []
    ids: set = set()
    for system_id in db.scalars(select(FindingRecord.ai_system_id).where(FindingRecord.control_id.in_(control_ids))):
        ids.add(system_id)
    for system_id in db.scalars(select(AssuranceRunRecord.ai_system_id).where(AssuranceRunRecord.control_id.in_(control_ids))):
        ids.add(system_id)
    evidence_ids = list(
        db.scalars(select(EvidenceControlLink.evidence_id).where(EvidenceControlLink.control_id.in_(control_ids)))
    )
    if evidence_ids:
        for system_id in db.scalars(
            select(EvidenceSystemLink.ai_system_id).where(EvidenceSystemLink.evidence_id.in_(evidence_ids))
        ):
            ids.add(system_id)
    ctrl002 = db.scalar(
        select(ControlRecord).where(ControlRecord.identifier == CTRL_002, ControlRecord.id.in_(control_ids))
    )
    if ctrl002 is not None:
        demo = db.scalar(
            select(AISystemRecord).where(
                AISystemRecord.name == DEMO_SYSTEM_NAME,
                AISystemRecord.environment == DEMO_ENVIRONMENT,
            )
        )
        if demo is not None:
            ids.add(demo.id)
    if not ids:
        return []
    return list(db.scalars(select(AISystemRecord).where(AISystemRecord.id.in_(ids)).order_by(AISystemRecord.name)))


def load_threat_summary(db: Session, threat: IntelThreat) -> dict:
    techniques = list(
        db.scalars(select(IntelTechnique).where(IntelTechnique.threat_id == threat.id).order_by(IntelTechnique.key))
    )
    mapped = 0
    items = []
    for item in techniques:
        impact = load_technique_impact(db, item)
        if impact["mapped"]:
            mapped += 1
        items.append((item, impact))
    return {
        "id": str(threat.id),
        "key": threat.key,
        "title": threat.title,
        "statement": threat.statement,
        "catalog_version": threat.catalog_version,
        "informational_only": bool(threat.informational_only),
        "technique_count": len(techniques),
        "mapped_techniques": mapped,
        "legal_compliance_claim": False,
        "catalog_complete": False,
        "items": items,
    }


def intel_totals(db: Session) -> dict:
    threats = list(db.scalars(select(IntelThreat)))
    techniques = list(db.scalars(select(IntelTechnique)))
    advisories = list(db.scalars(select(IntelAdvisory)))
    mapped = 0
    for item in techniques:
        if load_technique_impact(db, item)["mapped"]:
            mapped += 1
    test_count = len(list(db.scalars(select(IntelTechniqueTest))))
    return {
        "threat_count": len(threats),
        "technique_count": len(techniques),
        "advisory_count": len(advisories),
        "mapped_techniques": mapped,
        "suggested_tests": test_count,
        "catalog_complete": False,
        "catalog_version": CATALOG_VERSION,
        "legal_compliance_claim": False,
        "autonomous_attack": False,
    }
