from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.domain.enums import RecordOrigin
from threatsight_api.persistence.models import (
    AISystemRecord,
    AssuranceRunRecord,
    ControlRecord,
    EvidenceControlLink,
    EvidenceRecord,
    EvidenceSystemLink,
    FindingRecord,
    RequirementControlLink,
)

CTRL_002 = "CTRL-002"


def resolve_list_scope(db: Session, scope: str | None) -> tuple[str, set | None]:
    requested = (scope or "all").strip().lower()
    if requested not in {"showcase", "all"}:
        requested = "all"
    if requested != "showcase":
        return "all", None
    systems = list(
        db.scalars(select(AISystemRecord).where(AISystemRecord.record_origin == RecordOrigin.SHOWCASE.value))
    )
    return "showcase", {item.id for item in systems}


def showcase_control_ids(db: Session, system_ids: set) -> set:
    ids: set = set()
    if system_ids:
        for finding in db.scalars(select(FindingRecord).where(FindingRecord.ai_system_id.in_(system_ids))):
            ids.add(finding.control_id)
        evidence_ids = list(
            db.scalars(select(EvidenceSystemLink.evidence_id).where(EvidenceSystemLink.ai_system_id.in_(system_ids)))
        )
        if evidence_ids:
            for control_id in db.scalars(
                select(EvidenceControlLink.control_id).where(EvidenceControlLink.evidence_id.in_(evidence_ids))
            ):
                ids.add(control_id)
        for control_id in db.scalars(
            select(AssuranceRunRecord.control_id).where(AssuranceRunRecord.ai_system_id.in_(system_ids))
        ):
            ids.add(control_id)
    ctrl = db.scalar(select(ControlRecord).where(ControlRecord.identifier == CTRL_002))
    if ctrl is not None:
        ids.add(ctrl.id)
    return ids


def scoped_systems(db: Session, system_ids: set | None, *, limit: int, offset: int) -> list[AISystemRecord]:
    stmt = select(AISystemRecord).order_by(AISystemRecord.created_at)
    if system_ids is not None:
        if not system_ids:
            return []
        stmt = stmt.where(AISystemRecord.id.in_(system_ids))
    return list(db.scalars(stmt.offset(offset).limit(limit)))


def scoped_controls(db: Session, system_ids: set | None) -> set | None:
    if system_ids is None:
        return None
    return showcase_control_ids(db, system_ids)


def scoped_evidence_ids(db: Session, system_ids: set | None) -> set | None:
    if system_ids is None:
        return None
    if not system_ids:
        return set()
    ids = set(db.scalars(select(EvidenceSystemLink.evidence_id).where(EvidenceSystemLink.ai_system_id.in_(system_ids))))
    control_ids = showcase_control_ids(db, system_ids)
    if control_ids:
        ids |= set(
            db.scalars(select(EvidenceControlLink.evidence_id).where(EvidenceControlLink.control_id.in_(control_ids)))
        )
    labelled = set(
        db.scalars(
            select(EvidenceRecord.id).where(
                EvidenceRecord.title == "Labelled gateway policy attestation",
            )
        )
    )
    return ids | labelled


def scoped_requirement_ids(db: Session, system_ids: set | None) -> set | None:
    if system_ids is None:
        return None
    control_ids = showcase_control_ids(db, system_ids)
    if not control_ids:
        return set()
    return set(
        db.scalars(select(RequirementControlLink.requirement_id).where(RequirementControlLink.control_id.in_(control_ids)))
    )


def scoped_finding_filter(system_ids: set | None):
    if system_ids is None:
        return None
    return FindingRecord.ai_system_id.in_(system_ids) if system_ids else False
