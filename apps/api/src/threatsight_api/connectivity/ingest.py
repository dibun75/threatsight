from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.connectivity.contract import SOURCE_KINDS, ConnectivityIngestError
from threatsight_api.domain.enums import AuditAction
from threatsight_api.persistence.models import AgentEvent, AISystemRecord
from threatsight_api.services.audit import record_audit

MAX_JSON_BYTES = 8192


def ingest_event(db: Session, actor: str, payload: dict) -> AgentEvent:
    system_id = payload.get("ai_system_id")
    if not system_id:
        raise ConnectivityIngestError("ai_system_id is required")
    system = db.get(AISystemRecord, system_id)
    if system is None:
        raise ConnectivityIngestError("AI system not found")
    source_kind = str(payload.get("source_kind") or "").strip()
    if source_kind not in SOURCE_KINDS:
        raise ConnectivityIngestError("source_kind must be http_assessment, gateway, sdk, or otel")
    if payload.get("runtime_firewall") or payload.get("block") or payload.get("enforce"):
        raise ConnectivityIngestError("Passive ingest does not accept runtime firewall actions")
    arguments = _bounded_object(payload.get("arguments"), "arguments")
    authorization = _bounded_object(payload.get("authorization_context"), "authorization_context")
    result_meta = _bounded_object(payload.get("result_metadata"), "result_metadata")
    occurred = payload.get("occurred_at")
    if occurred is None:
        occurred_at = datetime.now(UTC)
    elif isinstance(occurred, datetime):
        occurred_at = occurred if occurred.tzinfo else occurred.replace(tzinfo=UTC)
    else:
        raise ConnectivityIngestError("occurred_at must be a timestamp")
    event = AgentEvent(
        ai_system_id=system.id,
        source_kind=source_kind,
        agent_id=_clip(payload.get("agent_id"), 200),
        session_id=_clip(payload.get("session_id"), 200),
        user_context=_clip(payload.get("user_context"), 500),
        tool_name=_clip(payload.get("tool_name"), 200),
        arguments=arguments,
        authorization_context=authorization,
        result_metadata={**result_meta, "runtime_firewall": False, "enforcement": "none"},
        occurred_at=occurred_at,
        correlation_id=_clip(payload.get("correlation_id"), 128),
        labelled_synthetic=bool(payload.get("labelled_synthetic")),
    )
    db.add(event)
    db.flush()
    record_audit(
        db,
        entity_type="agent_event",
        entity_id=event.id,
        action=AuditAction.CREATE,
        actor=actor,
        payload={
            "ai_system_id": str(system.id),
            "source_kind": source_kind,
            "tool_name": event.tool_name,
            "labelled_synthetic": event.labelled_synthetic,
            "runtime_firewall": False,
            "legal_compliance_claim": False,
        },
    )
    return event


def list_events(db: Session, system_id, *, limit: int = 50) -> list[AgentEvent]:
    stmt = select(AgentEvent).order_by(AgentEvent.occurred_at.desc()).limit(limit)
    if system_id is not None:
        stmt = stmt.where(AgentEvent.ai_system_id == system_id)
    return list(db.scalars(stmt))


def event_to_dict(event: AgentEvent) -> dict:
    return {
        "id": str(event.id),
        "ai_system_id": str(event.ai_system_id),
        "source_kind": event.source_kind,
        "agent_id": event.agent_id,
        "session_id": event.session_id,
        "user_context": event.user_context,
        "tool_name": event.tool_name,
        "arguments": event.arguments or {},
        "authorization_context": event.authorization_context or {},
        "result_metadata": event.result_metadata or {},
        "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
        "correlation_id": event.correlation_id,
        "labelled_synthetic": bool(event.labelled_synthetic),
        "runtime_firewall": False,
        "legal_compliance_claim": False,
    }


def _clip(value, length: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:length] if text else None


def _bounded_object(value, label: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConnectivityIngestError(f"{label} must be an object")
    encoded = json.dumps(value, default=str)
    if len(encoded.encode()) > MAX_JSON_BYTES:
        raise ConnectivityIngestError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
    return value
