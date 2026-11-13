from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from threatsight_api.domain.enums import AuditAction
from threatsight_api.persistence.models import AuditEvent


def record_audit(
    session: Session,
    *,
    entity_type: str,
    entity_id: uuid.UUID,
    action: AuditAction | str,
    actor: str,
    payload: dict | None = None,
) -> AuditEvent:
    event = AuditEvent(
        entity_type=entity_type,
        entity_id=entity_id,
        action=str(action),
        actor=actor,
        payload=payload or {},
    )
    session.add(event)
    return event
