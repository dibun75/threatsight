from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.api.schemas import ControlOut
from threatsight_api.api.systems import evidence_to_out
from threatsight_api.config import get_settings
from threatsight_api.persistence.models import (
    AISystemRecord,
    AuditEvent,
    ControlFrameworkLink,
    ControlRecord,
    EvidenceRecord,
    FindingRecord,
    FrameworkReference,
    RequirementControlLink,
    RequirementRecord,
)
from threatsight_api.services.dashboard import findings_to_out
from threatsight_api.services.freshness import (
    control_observation,
    latest_evidence_by_control,
    latest_runs_by_control,
)

FORMAT = "threatsight.export.v1"
GRC_FORMAT = "threatsight.grc.v1"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def envelope(*, kind: str, items: list, extra: dict | None = None) -> dict:
    settings = get_settings()
    payload = {
        "format": FORMAT,
        "kind": kind,
        "product": settings.product_name,
        "version": settings.product_version,
        "milestone": settings.milestone,
        "exported_at": _now(),
        "item_count": len(items),
        "legal_compliance_claim": False,
        "items": items,
    }
    if extra:
        payload.update(extra)
    return payload


def export_findings(db: Session, limit: int) -> dict:
    rows = list(db.scalars(select(FindingRecord).order_by(FindingRecord.created_at.desc()).limit(limit)))
    return envelope(kind="findings", items=[item.model_dump(mode="json") for item in findings_to_out(db, rows)])


def export_evidence(db: Session, limit: int) -> dict:
    rows = list(db.scalars(select(EvidenceRecord).order_by(EvidenceRecord.created_at.desc()).limit(limit)))
    items = [evidence_to_out(row, db).model_dump(mode="json") for row in rows]
    return envelope(kind="evidence", items=items)


def export_controls(db: Session, limit: int) -> dict:
    rows = list(db.scalars(select(ControlRecord).order_by(ControlRecord.identifier).limit(limit)))
    items = [ControlOut.model_validate(row).model_dump(mode="json") for row in rows]
    return envelope(kind="controls", items=items)


def export_audit(db: Session, limit: int) -> dict:
    rows = list(db.scalars(select(AuditEvent).order_by(AuditEvent.at.desc()).limit(limit)))
    items = [
        {
            "id": str(row.id),
            "entity_type": row.entity_type,
            "entity_id": str(row.entity_id),
            "action": row.action,
            "actor": row.actor,
            "at": row.at.isoformat() if row.at else None,
            "payload": row.payload,
        }
        for row in rows
    ]
    return envelope(kind="audit", items=items)


def export_grc_bundle(db: Session, limit: int) -> dict:
    settings = get_settings()
    systems = list(db.scalars(select(AISystemRecord).order_by(AISystemRecord.name).limit(limit)))
    controls = list(db.scalars(select(ControlRecord).order_by(ControlRecord.identifier).limit(limit)))
    requirements = list(db.scalars(select(RequirementRecord).order_by(RequirementRecord.title).limit(limit)))
    findings = export_findings(db, limit)["items"]
    evidence = export_evidence(db, limit)["items"]
    return {
        "format": GRC_FORMAT,
        "product": settings.product_name,
        "version": settings.product_version,
        "milestone": settings.milestone,
        "exported_at": _now(),
        "legal_compliance_claim": False,
        "integration": "saidot_class_exchange",
        "connector": False,
        "systems": [
            {
                "id": str(item.id),
                "name": item.name,
                "owner": item.owner,
                "environment": item.environment,
                "lifecycle": item.lifecycle,
            }
            for item in systems
        ],
        "requirements": [
            {
                "id": str(item.id),
                "title": item.title,
                "status": item.status,
                "source_type": item.source_type,
            }
            for item in requirements
        ],
        "controls": [ControlOut.model_validate(item).model_dump(mode="json") for item in controls],
        "evidence": evidence,
        "findings": findings,
    }


def export_control_matrix(db: Session, limit: int, scope: str | None = None) -> dict:
    from threatsight_api.services.scope import resolve_list_scope, scoped_controls

    settings = get_settings()
    _, system_ids = resolve_list_scope(db, scope)
    control_ids = scoped_controls(db, system_ids)
    stmt = select(ControlRecord).order_by(ControlRecord.identifier)
    if control_ids is not None:
        if not control_ids:
            return envelope(kind="control_matrix", items=[], extra={"freshness_window_days": settings.evidence_fresh_days})
        stmt = stmt.where(ControlRecord.id.in_(control_ids))
    controls = list(db.scalars(stmt.limit(limit)))
    runs = latest_runs_by_control(db)
    evidence_map = latest_evidence_by_control(db)
    requirements = {row.id: row for row in db.scalars(select(RequirementRecord))}
    reqs_by_control: dict = {}
    for link in db.scalars(select(RequirementControlLink)):
        requirement = requirements.get(link.requirement_id)
        if requirement is None:
            continue
        reqs_by_control.setdefault(link.control_id, []).append(requirement.title)
    references = {row.id: row for row in db.scalars(select(FrameworkReference))}
    frameworks_by_control: dict = {}
    for link in db.scalars(select(ControlFrameworkLink)):
        reference = references.get(link.framework_reference_id)
        if reference is None:
            continue
        frameworks_by_control.setdefault(link.control_id, []).append(
            f"{reference.framework_key}:{reference.reference_code}"
        )
    items = []
    for control in controls:
        observation = control_observation(db, control.id, runs=runs, evidence=evidence_map)
        items.append(
            {
                "control": control.identifier,
                "control_id": str(control.id),
                "requirement": "; ".join(reqs_by_control.get(control.id, [])) or None,
                "test": observation["scenario_key"],
                "result": observation["result"],
                "evidence": observation["evidence_id"],
                "owner": control.owner,
                "framework": "; ".join(frameworks_by_control.get(control.id, [])) or None,
                "freshness": observation["freshness"],
                "observed_at": observation["observed_at"].isoformat() if observation["observed_at"] else None,
            }
        )
    return envelope(
        kind="control_matrix",
        items=items,
        extra={
            "freshness_window_days": settings.evidence_fresh_days,
            "freshness_states": ["FRESH", "STALE", "UNTESTED"],
            "llm_authored": False,
        },
    )


def findings_csv(payload: dict) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["id", "title", "status", "severity", "verdict", "control_identifier", "ai_system_name"],
    )
    writer.writeheader()
    for item in payload["items"]:
        writer.writerow(
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "status": item.get("status"),
                "severity": item.get("severity"),
                "verdict": item.get("verdict"),
                "control_identifier": item.get("control_identifier"),
                "ai_system_name": item.get("ai_system_name"),
            }
        )
    return buffer.getvalue()


def control_matrix_csv(payload: dict) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["control", "requirement", "test", "result", "evidence", "owner", "framework", "freshness"],
    )
    writer.writeheader()
    for item in payload["items"]:
        writer.writerow(
            {
                "control": item.get("control"),
                "requirement": item.get("requirement") or "",
                "test": item.get("test") or "",
                "result": item.get("result") or "",
                "evidence": item.get("evidence") or "",
                "owner": item.get("owner"),
                "framework": item.get("framework") or "",
                "freshness": item.get("freshness"),
            }
        )
    return buffer.getvalue()


def audit_csv(payload: dict) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["id", "at", "actor", "action", "entity_type", "entity_id"])
    writer.writeheader()
    for item in payload["items"]:
        writer.writerow(
            {
                "id": item.get("id"),
                "at": item.get("at"),
                "actor": item.get("actor"),
                "action": item.get("action"),
                "entity_type": item.get("entity_type"),
                "entity_id": item.get("entity_id"),
            }
        )
    return buffer.getvalue()
