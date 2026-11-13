from __future__ import annotations

import uuid

from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select
from starlette.responses import Response

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, require_entity
from threatsight_api.api.schemas import RequirementCreate, RequirementOut, RequirementUpdate
from threatsight_api.domain.enums import AuditAction
from threatsight_api.persistence.models import RequirementRecord
from threatsight_api.services.audit import record_audit
from threatsight_api.services.scope import resolve_list_scope, scoped_requirement_ids

router = APIRouter(prefix="/requirements", tags=["requirements"])


@router.post("", status_code=201, response_model=RequirementOut)
def create_requirement(body: RequirementCreate, db: DbSession, actor: Actor) -> RequirementRecord:
    record = RequirementRecord(**body.model_dump(mode="json"), version=1)
    db.add(record)
    db.flush()
    record_audit(
        db,
        entity_type="requirement",
        entity_id=record.id,
        action=AuditAction.CREATE,
        actor=actor,
        payload={"title": record.title, "status": record.status},
    )
    return record


@router.get("", response_model=list[RequirementOut])
def list_requirements(
    db: DbSession,
    limit: Limit = 50,
    offset: Offset = 0,
    scope: Annotated[str | None, Query(max_length=16)] = None,
) -> list[RequirementRecord]:
    _, system_ids = resolve_list_scope(db, scope)
    req_ids = scoped_requirement_ids(db, system_ids)
    stmt = select(RequirementRecord).order_by(RequirementRecord.created_at)
    if req_ids is not None:
        if not req_ids:
            return []
        stmt = stmt.where(RequirementRecord.id.in_(req_ids))
    return list(db.scalars(stmt.offset(offset).limit(limit)))


@router.get("/{requirement_id}", response_model=RequirementOut)
def get_requirement(requirement_id: uuid.UUID, db: DbSession) -> RequirementRecord:
    return require_entity(db, RequirementRecord, requirement_id, "Requirement")


@router.patch("/{requirement_id}", response_model=RequirementOut)
def update_requirement(
    requirement_id: uuid.UUID,
    body: RequirementUpdate,
    db: DbSession,
    actor: Actor,
) -> RequirementRecord:
    record = require_entity(db, RequirementRecord, requirement_id, "Requirement")
    data = body.model_dump(mode="json", exclude_unset=True)
    before = {}
    after = {}
    for key, value in data.items():
        previous = getattr(record, key)
        if previous != value:
            before[key] = previous
            after[key] = value
            setattr(record, key, value)
    if after:
        record.version += 1
        record_audit(
            db,
            entity_type="requirement",
            entity_id=record.id,
            action=AuditAction.UPDATE,
            actor=actor,
            payload={"before": before, "after": after},
        )
    return record


@router.delete("/{requirement_id}", status_code=204)
def delete_requirement(requirement_id: uuid.UUID, db: DbSession, actor: Actor) -> Response:
    record = require_entity(db, RequirementRecord, requirement_id, "Requirement")
    record_audit(
        db,
        entity_type="requirement",
        entity_id=record.id,
        action=AuditAction.DELETE,
        actor=actor,
        payload={"title": record.title},
    )
    db.delete(record)
    return Response(status_code=204)
