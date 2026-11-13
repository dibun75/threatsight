from __future__ import annotations

import uuid

from typing import Annotated

from fastapi import APIRouter, Query, Response
from sqlalchemy import case, select

from threatsight_api.api.deps import Actor, DbSession, Limit, Offset, WorkspaceScope, require_entity
from threatsight_api.evidence_scope import service_evidence_ids
from threatsight_api.api.schemas import EvidenceCreate, EvidenceOut, EvidenceUpdate
from threatsight_api.api.systems import evidence_to_out
from threatsight_api.domain.enums import AuditAction
from threatsight_api.persistence.models import (
    AISystemRecord,
    ControlRecord,
    EvidenceControlLink,
    EvidenceRecord,
    EvidenceSystemLink,
)
from threatsight_api.services.audit import record_audit
from threatsight_api.services.scope import resolve_list_scope, scoped_evidence_ids

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.post("", status_code=201, response_model=EvidenceOut)
def create_evidence(body: EvidenceCreate, db: DbSession, actor: Actor) -> EvidenceOut:
    data = body.model_dump()
    control_ids = list(data.pop("control_ids"))
    system_ids = list(data.pop("ai_system_ids"))
    for key in ("evidence_type", "status"):
        value = data.get(key)
        if value is not None:
            data[key] = str(value)
    record = EvidenceRecord(**data)
    db.add(record)
    db.flush()
    for control_id in control_ids:
        require_entity(db, ControlRecord, control_id, "Control")
        db.add(EvidenceControlLink(evidence_id=record.id, control_id=control_id))
    for system_id in system_ids:
        require_entity(db, AISystemRecord, system_id, "AI system")
        db.add(EvidenceSystemLink(evidence_id=record.id, ai_system_id=system_id))
    record_audit(
        db,
        entity_type="evidence",
        entity_id=record.id,
        action=AuditAction.CREATE,
        actor=actor,
        payload={"title": record.title, "control_ids": [str(item) for item in control_ids]},
    )
    db.flush()
    return evidence_to_out(record, db)


@router.get("", response_model=list[EvidenceOut])
def list_evidence(
    db: DbSession,
    response: Response,
    workspace: WorkspaceScope,
    limit: Limit = 50,
    offset: Offset = 0,
    scope: Annotated[str | None, Query(max_length=16)] = None,
    service: Annotated[uuid.UUID | None, Query()] = None,
) -> list[EvidenceOut]:
    hashed_first = case((EvidenceRecord.integrity_hash.is_not(None), 0), else_=1)
    artifact_first = case((EvidenceRecord.evidence_type == "test_artifact", 0), else_=1)
    stmt = select(EvidenceRecord).order_by(hashed_first, artifact_first, EvidenceRecord.created_at.desc())
    if service is not None:
        evidence_ids = service_evidence_ids(db, workspace.tenant_id, workspace.id, service)
        response.headers["X-Total-Count"] = str(len(evidence_ids))
        if not evidence_ids:
            return []
        stmt = stmt.where(EvidenceRecord.id.in_(evidence_ids))
    else:
        _, system_ids = resolve_list_scope(db, scope)
        evidence_ids = scoped_evidence_ids(db, system_ids)
        if evidence_ids is not None:
            if not evidence_ids:
                return []
            stmt = stmt.where(EvidenceRecord.id.in_(evidence_ids))
    rows = list(db.scalars(stmt.offset(offset).limit(limit)))
    return [evidence_to_out(row, db) for row in rows]


@router.get("/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: uuid.UUID, db: DbSession) -> EvidenceOut:
    record = require_entity(db, EvidenceRecord, evidence_id, "Evidence")
    return evidence_to_out(record, db)


@router.patch("/{evidence_id}", response_model=EvidenceOut)
def update_evidence(evidence_id: uuid.UUID, body: EvidenceUpdate, db: DbSession, actor: Actor) -> EvidenceOut:
    record = require_entity(db, EvidenceRecord, evidence_id, "Evidence")
    data = body.model_dump(mode="json", exclude_unset=True)
    before = {}
    after = {}
    for key, value in data.items():
        previous = getattr(record, key)
        if previous != value:
            before[key] = str(previous) if previous is not None else None
            after[key] = value
            setattr(record, key, value)
    if after:
        record_audit(
            db,
            entity_type="evidence",
            entity_id=record.id,
            action=AuditAction.UPDATE,
            actor=actor,
            payload={"before": before, "after": after},
        )
    return evidence_to_out(record, db)


@router.delete("/{evidence_id}", status_code=204)
def delete_evidence(evidence_id: uuid.UUID, db: DbSession, actor: Actor) -> Response:
    record = require_entity(db, EvidenceRecord, evidence_id, "Evidence")
    record_audit(
        db,
        entity_type="evidence",
        entity_id=record.id,
        action=AuditAction.DELETE,
        actor=actor,
        payload={"title": record.title},
    )
    db.delete(record)
    return Response(status_code=204)
