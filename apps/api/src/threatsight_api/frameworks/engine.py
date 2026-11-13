from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.assurance.catalog import CTRL_002
from threatsight_api.domain.enums import AuditAction
from threatsight_api.frameworks.catalog import CATALOG_ITEMS, CATALOG_VERSION, CTRL002_SUGGESTIONS, FRAMEWORKS
from threatsight_api.frameworks.coverage import COVERAGE_KEYS, count_coverage, coverage_from_control_statuses
from threatsight_api.persistence.models import ControlFrameworkLink, ControlRecord, FrameworkReference
from threatsight_api.services.audit import record_audit


def sync_catalog(db: Session) -> list[FrameworkReference]:
    rows: list[FrameworkReference] = []
    for item in CATALOG_ITEMS:
        record = db.scalar(
            select(FrameworkReference).where(
                FrameworkReference.framework_key == item.framework_key,
                FrameworkReference.reference_code == item.reference_code,
            )
        )
        if record is None:
            record = FrameworkReference(
                framework_key=item.framework_key,
                reference_code=item.reference_code,
                title=item.title[:300],
                locator=item.locator,
                statement=item.statement,
                source_kind=item.source_kind,
                catalog_version=CATALOG_VERSION,
                informational_only=True,
            )
            db.add(record)
            db.flush()
        else:
            record.title = item.title[:300]
            record.locator = item.locator
            record.statement = item.statement
            record.source_kind = item.source_kind
            record.catalog_version = CATALOG_VERSION
            record.informational_only = True
            db.flush()
        rows.append(record)
    return rows


def bootstrap_frameworks(db: Session, actor: str) -> dict:
    rows = sync_catalog(db)
    control = db.scalar(select(ControlRecord).where(ControlRecord.identifier == CTRL_002))
    mapped: list[str] = []
    if control is not None:
        by_code = {(item.framework_key, item.reference_code): item for item in rows}
        for key, code in CTRL002_SUGGESTIONS:
            reference = by_code.get((key, code))
            if reference is None:
                continue
            existing = db.scalar(
                select(ControlFrameworkLink).where(
                    ControlFrameworkLink.control_id == control.id,
                    ControlFrameworkLink.framework_reference_id == reference.id,
                )
            )
            if existing is not None:
                mapped.append(f"{key}:{code}")
                continue
            link = ControlFrameworkLink(
                control_id=control.id,
                framework_reference_id=reference.id,
                note="Informational M6 mapping for CTRL-002. Not a legal conclusion.",
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
                    "framework_reference_id": str(reference.id),
                    "framework_key": key,
                    "reference_code": code,
                    "informational_only": True,
                    "legal_compliance_claim": False,
                    "source": "m6-bootstrap",
                },
            )
            mapped.append(f"{key}:{code}")
    return {
        "catalog_version": CATALOG_VERSION,
        "catalog_complete": False,
        "legal_compliance_claim": False,
        "item_count": len(rows),
        "control_id": str(control.id) if control else None,
        "mapped_references": mapped,
        "frameworks": [item.key for item in FRAMEWORKS],
    }


def load_item_coverage(db: Session, reference: FrameworkReference) -> dict:
    links = list(
        db.scalars(
            select(ControlFrameworkLink).where(ControlFrameworkLink.framework_reference_id == reference.id)
        )
    )
    controls: list[ControlRecord] = []
    for link in links:
        control = db.get(ControlRecord, link.control_id)
        if control is not None:
            controls.append(control)
    statuses = [item.assurance_status for item in controls]
    return {
        "mapped": bool(controls),
        "coverage_status": coverage_from_control_statuses(statuses),
        "control_count": len(controls),
        "controls": controls,
        "legal_compliance_claim": False,
        "informational_only": True,
        "catalog_complete": False,
    }


def load_framework_summaries(db: Session) -> list[dict]:
    references = list(db.scalars(select(FrameworkReference).order_by(FrameworkReference.framework_key, FrameworkReference.reference_code)))
    by_key: dict[str, list[FrameworkReference]] = {}
    for item in references:
        by_key.setdefault(item.framework_key, []).append(item)
    summaries = []
    for meta in FRAMEWORKS:
        items = by_key.get(meta.key, [])
        payloads = [load_item_coverage(db, item) for item in items]
        coverages = [item["coverage_status"] for item in payloads]
        mapped = sum(1 for item in payloads if item["mapped"])
        summaries.append(
            {
                "key": meta.key,
                "title": meta.title,
                "locator": meta.locator,
                "item_count": len(items),
                "mapped_items": mapped,
                "by_coverage_status": count_coverage(coverages, COVERAGE_KEYS),
                "catalog_complete": False,
                "catalog_version": CATALOG_VERSION,
                "legal_compliance_claim": False,
            }
        )
    return summaries


def coverage_totals(db: Session) -> dict:
    references = list(db.scalars(select(FrameworkReference)))
    coverages = []
    mapped = 0
    for item in references:
        payload = load_item_coverage(db, item)
        coverages.append(payload["coverage_status"])
        if payload["mapped"]:
            mapped += 1
    return {
        "item_count": len(references),
        "mapped_items": mapped,
        "by_coverage_status": count_coverage(coverages, COVERAGE_KEYS),
        "catalog_complete": False,
        "catalog_version": CATALOG_VERSION,
        "legal_compliance_claim": False,
    }
