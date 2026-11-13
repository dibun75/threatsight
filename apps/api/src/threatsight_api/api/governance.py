from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, require_entity
from threatsight_api.api.schemas import (
    FrameworkMapOut,
    FrameworkReferenceCreate,
    FrameworkReferenceOut,
    ReviewCreate,
    ReviewOut,
    AuditOut,
)
from threatsight_api.api.systems import _framework_map_out
from threatsight_api.domain.enums import AuditAction, RequirementStatus, ReviewDecision, ReviewableEntity
from threatsight_api.persistence.models import (
    ControlFrameworkLink,
    ControlRecord,
    EvidenceRecord,
    FrameworkReference,
    RequirementControlLink,
    RequirementRecord,
    ReviewRecord,
    AuditEvent,
)
from threatsight_api.services.audit import record_audit

frameworks_router = APIRouter(prefix="/framework-references", tags=["frameworks"])
reviews_router = APIRouter(prefix="/reviews", tags=["reviews"])
audit_router = APIRouter(prefix="/audit", tags=["audit"])


@frameworks_router.post("", status_code=201, response_model=FrameworkReferenceOut)
def create_framework_reference(body: FrameworkReferenceCreate, db: DbSession, actor: Actor) -> FrameworkReference:
    record = FrameworkReference(**body.model_dump(mode="json"))
    db.add(record)
    try:
        db.flush()
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Framework reference already exists") from exc
    record_audit(
        db,
        entity_type="framework_reference",
        entity_id=record.id,
        action=AuditAction.CREATE,
        actor=actor,
        payload={"framework_key": record.framework_key, "reference_code": record.reference_code},
    )
    return record


@frameworks_router.get("", response_model=list[FrameworkReferenceOut])
def list_framework_references(
    db: DbSession,
    framework_key: str | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> list[FrameworkReference]:
    stmt = select(FrameworkReference).order_by(FrameworkReference.framework_key, FrameworkReference.reference_code)
    if framework_key:
        stmt = stmt.where(FrameworkReference.framework_key == framework_key)
    return list(db.scalars(stmt.offset(offset).limit(limit)))


@reviews_router.post("", status_code=201, response_model=ReviewOut)
def create_review(body: ReviewCreate, db: DbSession, actor: Actor) -> ReviewRecord:
    entity_type = body.entity_type.value
    if body.entity_type == ReviewableEntity.CANDIDATE:
        raise HTTPException(
            status_code=400,
            detail="Review extraction candidates via POST /api/v1/candidates/{id}/review",
        )
    if body.entity_type == ReviewableEntity.REQUIREMENT:
        require_entity(db, RequirementRecord, body.entity_id, "Requirement")
    elif body.entity_type == ReviewableEntity.CONTROL:
        require_entity(db, ControlRecord, body.entity_id, "Control")
    elif body.entity_type == ReviewableEntity.EVIDENCE:
        require_entity(db, EvidenceRecord, body.entity_id, "Evidence")
    elif body.entity_type == ReviewableEntity.MAPPING:
        require_entity(db, RequirementControlLink, body.entity_id, "Mapping")
    record = ReviewRecord(
        entity_type=entity_type,
        entity_id=body.entity_id,
        reviewer=body.reviewer,
        decision=body.decision.value,
        comment=body.comment,
    )
    db.add(record)
    db.flush()
    _apply_review_side_effect(db, body)
    record_audit(
        db,
        entity_type=entity_type,
        entity_id=body.entity_id,
        action=AuditAction.REVIEW,
        actor=actor,
        payload={"reviewer": body.reviewer, "decision": body.decision.value, "review_id": str(record.id)},
    )
    return record


@reviews_router.get("", response_model=list[ReviewOut])
def list_reviews(
    db: DbSession,
    entity_type: ReviewableEntity | None = None,
    entity_id: uuid.UUID | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> list[ReviewRecord]:
    stmt = select(ReviewRecord).order_by(ReviewRecord.created_at)
    if entity_type is not None:
        stmt = stmt.where(ReviewRecord.entity_type == entity_type.value)
    if entity_id is not None:
        stmt = stmt.where(ReviewRecord.entity_id == entity_id)
    return list(db.scalars(stmt.offset(offset).limit(limit)))


@audit_router.get("", response_model=list[AuditOut])
def list_audit(
    db: DbSession,
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
    order: str = "asc",
) -> list[AuditEvent]:
    if order not in {"asc", "desc"}:
        raise HTTPException(status_code=400, detail="order must be asc or desc")
    stmt = select(AuditEvent).order_by(AuditEvent.at.desc() if order == "desc" else AuditEvent.at)
    if entity_type:
        if len(entity_type) > 32:
            raise HTTPException(status_code=400, detail="Invalid entity_type")
        stmt = stmt.where(AuditEvent.entity_type == entity_type)
    if entity_id is not None:
        stmt = stmt.where(AuditEvent.entity_id == entity_id)
    return list(db.scalars(stmt.offset(offset).limit(limit)))


def _apply_review_side_effect(db: DbSession, body: ReviewCreate) -> None:
    if body.entity_type != ReviewableEntity.REQUIREMENT:
        return
    requirement = db.get(RequirementRecord, body.entity_id)
    if requirement is None:
        return
    mapping = {
        ReviewDecision.APPROVE: RequirementStatus.APPROVED.value,
        ReviewDecision.REJECT: RequirementStatus.REJECTED.value,
        ReviewDecision.DEFER: RequirementStatus.DEFERRED.value,
        ReviewDecision.REQUEST_CHANGES: RequirementStatus.EDITED.value,
    }
    requirement.status = mapping[body.decision]


def list_control_framework_maps(db, control_id: uuid.UUID) -> list[FrameworkMapOut]:
    links = list(
        db.scalars(select(ControlFrameworkLink).where(ControlFrameworkLink.control_id == control_id))
    )
    result = []
    for link in links:
        reference = db.get(FrameworkReference, link.framework_reference_id)
        if reference:
            result.append(_framework_map_out(link, reference))
    return result
