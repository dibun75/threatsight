from __future__ import annotations

import uuid
from datetime import UTC, datetime

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from starlette.responses import Response

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, require_entity
from threatsight_api.api.schemas import (
    AISystemCreate,
    AISystemOut,
    AISystemUpdate,
    AssuranceView,
    ControlCreate,
    ControlOut,
    ControlUpdate,
    EvidenceOut,
    FrameworkMapCreate,
    FrameworkMapOut,
    MappingCreate,
    MappingOut,
    RequirementOut,
    ReviewOut,
    SystemPostureOut,
)
from threatsight_api.domain.assurance import assert_assurance_status
from threatsight_api.domain.enums import AuditAction, ReviewableEntity
from threatsight_api.persistence.models import (
    AISystemRecord,
    ControlFrameworkLink,
    ControlRecord,
    EvidenceControlLink,
    EvidenceRecord,
    EvidenceSystemLink,
    FrameworkReference,
    RequirementControlLink,
    RequirementRecord,
    ReviewRecord,
)
from threatsight_api.services.audit import record_audit
from threatsight_api.services.freshness import control_observation, evidence_freshness_fields
from threatsight_api.services.dashboard import findings_to_out, load_system_graph, load_system_ops
from threatsight_api.services.identity import identity_for
from threatsight_api.services.scope import resolve_list_scope, scoped_controls, scoped_systems

systems_router = APIRouter(prefix="/systems", tags=["systems"])
controls_router = APIRouter(prefix="/controls", tags=["controls"])


def _apply(record, data: dict) -> dict:
    before = {}
    after = {}
    for key, value in data.items():
        if value is None:
            continue
        previous = getattr(record, key)
        if previous != value:
            before[key] = previous
            after[key] = value if not isinstance(value, datetime) else value.isoformat()
            setattr(record, key, value)
    return {"before": before, "after": after}


@systems_router.post("", status_code=201, response_model=AISystemOut)
def create_system(body: AISystemCreate, db: DbSession, actor: Actor) -> AISystemRecord:
    data = body.model_dump(mode="json")
    record = AISystemRecord(**data, record_origin="manual")
    db.add(record)
    db.flush()
    record_audit(
        db,
        entity_type="ai_system",
        entity_id=record.id,
        action=AuditAction.CREATE,
        actor=actor,
        payload={"name": record.name, "environment": record.environment},
    )
    return record


@systems_router.get("", response_model=list[AISystemOut])
def list_systems(
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    scope: Annotated[str | None, Query(max_length=16)] = None,
) -> list[AISystemRecord]:
    _, system_ids = resolve_list_scope(db, scope)
    return scoped_systems(db, system_ids, limit=limit, offset=offset)


@systems_router.get("/{system_id}/posture", response_model=SystemPostureOut)
def get_system_posture(system_id: uuid.UUID, db: DbSession) -> SystemPostureOut:
    system = require_entity(db, AISystemRecord, system_id, "AI system")
    graph = load_system_graph(db, system)
    ops = load_system_ops(db, system, graph)

    return SystemPostureOut(
        legal_compliance_claim=False,
        system=AISystemOut.model_validate(system),
        controls=[ControlOut.model_validate(item) for item in graph["controls"]],
        findings=findings_to_out(db, graph["findings"]),
        evidence=[evidence_to_out(item, db) for item in graph["evidence"]],
        requirements=[RequirementOut.model_validate(item) for item in graph["requirements"]],
        profile=ops["profile"],
        capabilities=ops["capabilities"],
        data_categories=ops["data_categories"],
        users_subjects=ops["users_subjects"],
        traces=ops["traces"],
        threat_exposure=ops["threat_exposure"],
        missing_information=ops["missing_information"],
        tests=ops["tests"],
        remediation_state=ops["remediation_state"],
        posture_summary=ops.get("posture_summary") or "NOT ASSESSED",
        identity=ops.get("identity") or {},
    )


@systems_router.get("/{system_id}", response_model=AISystemOut)
def get_system(system_id: uuid.UUID, db: DbSession) -> AISystemRecord:
    return require_entity(db, AISystemRecord, system_id, "AI system")


@systems_router.patch("/{system_id}", response_model=AISystemOut)
def update_system(system_id: uuid.UUID, body: AISystemUpdate, db: DbSession, actor: Actor) -> AISystemRecord:
    record = require_entity(db, AISystemRecord, system_id, "AI system")
    changes = _apply(record, body.model_dump(exclude_unset=True))
    if changes["after"]:
        record_audit(
            db,
            entity_type="ai_system",
            entity_id=record.id,
            action=AuditAction.UPDATE,
            actor=actor,
            payload=changes,
        )
    return record


@systems_router.delete("/{system_id}", status_code=204)
def delete_system(system_id: uuid.UUID, db: DbSession, actor: Actor) -> Response:
    record = require_entity(db, AISystemRecord, system_id, "AI system")
    record_audit(
        db,
        entity_type="ai_system",
        entity_id=record.id,
        action=AuditAction.DELETE,
        actor=actor,
        payload={"name": record.name},
    )
    db.delete(record)
    return Response(status_code=204)


@controls_router.post("", status_code=201, response_model=ControlOut)
def create_control(body: ControlCreate, db: DbSession, actor: Actor) -> ControlRecord:
    now = datetime.now(UTC)
    payload = body.model_dump(mode="json")
    record = ControlRecord(
        **payload,
        assurance_set_by=actor,
        assurance_set_at=now,
    )
    db.add(record)
    try:
        db.flush()
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Control identifier already exists") from exc
    record_audit(
        db,
        entity_type="control",
        entity_id=record.id,
        action=AuditAction.CREATE,
        actor=actor,
        payload={"identifier": record.identifier, "assurance_status": record.assurance_status},
    )
    return record


@controls_router.get("", response_model=list[ControlOut])
def list_controls(
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    q: Annotated[str | None, Query(max_length=200)] = None,
    assurance_status: Annotated[str | None, Query(max_length=64)] = None,
    latest_verdict: Annotated[str | None, Query(max_length=32)] = None,
    severity: Annotated[str | None, Query(max_length=32)] = None,
    scope: Annotated[str | None, Query(max_length=16)] = None,
) -> list[ControlRecord]:
    stmt = select(ControlRecord)
    _, system_ids = resolve_list_scope(db, scope)
    control_ids = scoped_controls(db, system_ids)
    if control_ids is not None:
        if not control_ids:
            return []
        stmt = stmt.where(ControlRecord.id.in_(control_ids))
    if q and q.strip():
        term = f"%{q.strip()}%"
        stmt = stmt.where(or_(ControlRecord.identifier.ilike(term), ControlRecord.title.ilike(term)))
    if assurance_status:
        try:
            stmt = stmt.where(ControlRecord.assurance_status == assert_assurance_status(assurance_status).value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if latest_verdict:
        stmt = stmt.where(ControlRecord.latest_verdict == latest_verdict)
    if severity:
        stmt = stmt.where(ControlRecord.severity == severity)
    return list(db.scalars(stmt.order_by(ControlRecord.identifier).offset(offset).limit(limit)))


@controls_router.get("/{control_id}", response_model=ControlOut)
def get_control(control_id: uuid.UUID, db: DbSession) -> ControlRecord:
    return require_entity(db, ControlRecord, control_id, "Control")


@controls_router.patch("/{control_id}", response_model=ControlOut)
def update_control(control_id: uuid.UUID, body: ControlUpdate, db: DbSession, actor: Actor) -> ControlRecord:
    record = require_entity(db, ControlRecord, control_id, "Control")
    data = body.model_dump(exclude_unset=True)
    status_changed = "assurance_status" in data and data["assurance_status"] != record.assurance_status
    changes = _apply(record, data)
    if changes["after"]:
        record.version += 1
        if status_changed:
            record.assurance_set_by = actor
            record.assurance_set_at = datetime.now(UTC)
        record_audit(
            db,
            entity_type="control",
            entity_id=record.id,
            action=AuditAction.STATUS_CHANGE if status_changed else AuditAction.UPDATE,
            actor=actor,
            payload=changes,
        )
    return record


@controls_router.delete("/{control_id}", status_code=204)
def delete_control(control_id: uuid.UUID, db: DbSession, actor: Actor) -> Response:
    record = require_entity(db, ControlRecord, control_id, "Control")
    record_audit(
        db,
        entity_type="control",
        entity_id=record.id,
        action=AuditAction.DELETE,
        actor=actor,
        payload={"identifier": record.identifier},
    )
    db.delete(record)
    return Response(status_code=204)


@controls_router.post("/{control_id}/requirements", status_code=201, response_model=MappingOut)
def map_requirement(control_id: uuid.UUID, body: MappingCreate, db: DbSession, actor: Actor) -> RequirementControlLink:
    control = require_entity(db, ControlRecord, control_id, "Control")
    require_entity(db, RequirementRecord, body.requirement_id, "Requirement")
    link = RequirementControlLink(
        requirement_id=body.requirement_id,
        control_id=control.id,
        rationale=body.rationale,
        provenance=body.provenance,
    )
    db.add(link)
    try:
        db.flush()
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Mapping already exists") from exc
    record_audit(
        db,
        entity_type="mapping",
        entity_id=link.id,
        action=AuditAction.MAP,
        actor=actor,
        payload={
            "requirement_id": str(body.requirement_id),
            "control_id": str(control.id),
            "informational_only": True,
        },
    )
    return link


@controls_router.delete("/{control_id}/requirements/{requirement_id}", status_code=204)
def unmap_requirement(
    control_id: uuid.UUID,
    requirement_id: uuid.UUID,
    db: DbSession,
    actor: Actor,
) -> Response:
    link = db.scalar(
        select(RequirementControlLink).where(
            RequirementControlLink.control_id == control_id,
            RequirementControlLink.requirement_id == requirement_id,
        )
    )
    if link is None:
        raise HTTPException(status_code=404, detail="Mapping not found")
    record_audit(
        db,
        entity_type="mapping",
        entity_id=link.id,
        action=AuditAction.UNMAP,
        actor=actor,
        payload={"requirement_id": str(requirement_id), "control_id": str(control_id)},
    )
    db.delete(link)
    return Response(status_code=204)


@controls_router.post("/{control_id}/evidence/{evidence_id}", status_code=201)
def link_evidence(
    control_id: uuid.UUID,
    evidence_id: uuid.UUID,
    db: DbSession,
    actor: Actor,
) -> dict:
    require_entity(db, ControlRecord, control_id, "Control")
    require_entity(db, EvidenceRecord, evidence_id, "Evidence")
    existing = db.get(EvidenceControlLink, (evidence_id, control_id))
    if existing:
        raise HTTPException(status_code=409, detail="Evidence already linked")
    db.add(EvidenceControlLink(evidence_id=evidence_id, control_id=control_id))
    record_audit(
        db,
        entity_type="control",
        entity_id=control_id,
        action=AuditAction.MAP,
        actor=actor,
        payload={"evidence_id": str(evidence_id)},
    )
    return {"control_id": str(control_id), "evidence_id": str(evidence_id)}


@controls_router.post("/{control_id}/framework-mappings", status_code=201, response_model=FrameworkMapOut)
def map_framework(
    control_id: uuid.UUID,
    body: FrameworkMapCreate,
    db: DbSession,
    actor: Actor,
) -> FrameworkMapOut:
    require_entity(db, ControlRecord, control_id, "Control")
    reference = require_entity(db, FrameworkReference, body.framework_reference_id, "Framework reference")
    link = ControlFrameworkLink(
        control_id=control_id,
        framework_reference_id=body.framework_reference_id,
        note=body.note,
    )
    db.add(link)
    try:
        db.flush()
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Framework mapping already exists") from exc
    record_audit(
        db,
        entity_type="control",
        entity_id=control_id,
        action=AuditAction.MAP,
        actor=actor,
        payload={
            "framework_reference_id": str(body.framework_reference_id),
            "informational_only": True,
            "legal_compliance_claim": False,
        },
    )
    return _framework_map_out(link, reference)


@controls_router.get("/{control_id}/assurance", response_model=AssuranceView)
def get_assurance(control_id: uuid.UUID, db: DbSession) -> AssuranceView:
    control = require_entity(db, ControlRecord, control_id, "Control")
    req_ids = [link.requirement_id for link in control.requirement_links]
    requirements = list(db.scalars(select(RequirementRecord).where(RequirementRecord.id.in_(req_ids)))) if req_ids else []
    evidence_ids = [link.evidence_id for link in control.evidence_links]
    evidence_rows = list(db.scalars(select(EvidenceRecord).where(EvidenceRecord.id.in_(evidence_ids)))) if evidence_ids else []
    framework_maps = []
    for link in control.framework_links:
        reference = db.get(FrameworkReference, link.framework_reference_id)
        if reference:
            framework_maps.append(_framework_map_out(link, reference))
    reviews = list(
        db.scalars(
            select(ReviewRecord)
            .where(ReviewRecord.entity_type == ReviewableEntity.CONTROL.value, ReviewRecord.entity_id == control.id)
            .order_by(ReviewRecord.created_at)
        )
    )
    observation = control_observation(db, control.id)
    return AssuranceView(
        control_id=control.id,
        identifier=control.identifier,
        title=control.title,
        assurance_status=control.assurance_status,
        assurance_rationale=control.assurance_rationale,
        requirements=[RequirementOut.model_validate(item) for item in requirements],
        evidence=[evidence_to_out(item, db) for item in evidence_rows],
        framework_mappings=framework_maps,
        reviews=[ReviewOut.model_validate(item) for item in reviews],
        latest_technical_verdict=control.latest_verdict,
        freshness=observation["freshness"],
        freshness_observed_at=observation["observed_at"],
        freshness_window_days=observation["window_days"],
    )


def _framework_map_out(link: ControlFrameworkLink, reference: FrameworkReference) -> FrameworkMapOut:
    return FrameworkMapOut(
        id=link.id,
        control_id=link.control_id,
        framework_reference_id=reference.id,
        framework_key=reference.framework_key,
        reference_code=reference.reference_code,
        title=reference.title,
        locator=reference.locator,
        note=link.note,
        informational_only=True,
        legal_compliance_claim=False,
    )


def evidence_to_out(record: EvidenceRecord, db) -> EvidenceOut:
    control_ids = list(
        db.scalars(select(EvidenceControlLink.control_id).where(EvidenceControlLink.evidence_id == record.id))
    )
    system_ids = list(
        db.scalars(select(EvidenceSystemLink.ai_system_id).where(EvidenceSystemLink.evidence_id == record.id))
    )
    freshness = evidence_freshness_fields(record)
    controls = list(db.scalars(select(ControlRecord).where(ControlRecord.id.in_(control_ids)))) if control_ids else []
    systems = list(db.scalars(select(AISystemRecord).where(AISystemRecord.id.in_(system_ids)))) if system_ids else []
    return EvidenceOut(
        id=record.id,
        title=record.title,
        description=record.description,
        evidence_type=record.evidence_type,
        source_reference=record.source_reference,
        provenance=record.provenance,
        collected_at=record.collected_at,
        owner=record.owner,
        status=record.status,
        document_ref=record.document_ref,
        integrity_hash=getattr(record, "integrity_hash", None),
        envelope=getattr(record, "envelope", None),
        control_ids=control_ids,
        ai_system_ids=system_ids,
        created_at=record.created_at,
        updated_at=record.updated_at,
        freshness=freshness["freshness"],
        freshness_window_days=freshness["freshness_window_days"],
        freshness_observed_at=freshness["freshness_observed_at"],
        control_labels=[item.identifier for item in controls],
        system_labels=[identity_for(item)["display_name"] for item in systems],
    )
