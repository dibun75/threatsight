from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.config import get_settings
from threatsight_api.domain.enums import EvidenceFreshness
from threatsight_api.domain.freshness import as_utc, classify_freshness
from threatsight_api.persistence.models import (
    AssuranceRunRecord,
    ControlRecord,
    EvidenceControlLink,
    EvidenceRecord,
)


def evidence_observed_at(record: EvidenceRecord) -> datetime | None:
    return as_utc(record.collected_at) or as_utc(record.created_at)


def run_observed_at(record: AssuranceRunRecord) -> datetime | None:
    return as_utc(record.finished_at) or as_utc(record.started_at)


def _later(left: datetime | None, right: datetime | None) -> datetime | None:
    if left is None:
        return right
    if right is None:
        return left
    return left if left >= right else right


def latest_runs_by_control(db: Session) -> dict[UUID, AssuranceRunRecord]:
    rows = list(db.scalars(select(AssuranceRunRecord).order_by(AssuranceRunRecord.started_at.desc())))
    latest: dict[UUID, AssuranceRunRecord] = {}
    for row in rows:
        latest.setdefault(row.control_id, row)
    return latest


def latest_evidence_by_control(db: Session) -> dict[UUID, EvidenceRecord]:
    links = list(db.scalars(select(EvidenceControlLink)))
    if not links:
        return {}
    records = {
        item.id: item
        for item in db.scalars(
            select(EvidenceRecord).where(EvidenceRecord.id.in_({link.evidence_id for link in links}))
        )
    }
    best: dict[UUID, EvidenceRecord] = {}
    for link in links:
        record = records.get(link.evidence_id)
        if record is None:
            continue
        current = best.get(link.control_id)
        if current is None or (evidence_observed_at(record) or datetime.min.replace(tzinfo=UTC)) > (
            evidence_observed_at(current) or datetime.min.replace(tzinfo=UTC)
        ):
            best[link.control_id] = record
    return best


def control_observation(
    db: Session,
    control_id: UUID,
    *,
    runs: dict[UUID, AssuranceRunRecord] | None = None,
    evidence: dict[UUID, EvidenceRecord] | None = None,
) -> dict:
    run = (runs or latest_runs_by_control(db)).get(control_id)
    record = (evidence or latest_evidence_by_control(db)).get(control_id)
    observed = _later(run_observed_at(run) if run else None, evidence_observed_at(record) if record else None)
    settings = get_settings()
    return {
        "freshness": classify_freshness(observed, window_days=settings.evidence_fresh_days),
        "observed_at": observed,
        "window_days": settings.evidence_fresh_days,
        "run_id": str(run.id) if run else None,
        "scenario_key": run.scenario_key if run else None,
        "result": run.verdict if run else None,
        "evidence_id": str(record.id) if record else (str(run.evidence_id) if run and run.evidence_id else None),
    }


def evidence_freshness_fields(record: EvidenceRecord) -> dict:
    settings = get_settings()
    observed = evidence_observed_at(record)
    return {
        "freshness": classify_freshness(observed, window_days=settings.evidence_fresh_days),
        "freshness_window_days": settings.evidence_fresh_days,
        "freshness_observed_at": observed,
    }


def freshness_totals(db: Session, *, controls=None, evidence_rows=None) -> dict:
    settings = get_settings()
    window = settings.evidence_fresh_days
    controls = list(controls) if controls is not None else list(db.scalars(select(ControlRecord)))
    evidence_rows = list(evidence_rows) if evidence_rows is not None else list(db.scalars(select(EvidenceRecord)))
    runs = latest_runs_by_control(db)
    linked = latest_evidence_by_control(db)
    control_counts = {item.value: 0 for item in EvidenceFreshness}
    for control in controls:
        state = control_observation(db, control.id, runs=runs, evidence=linked)["freshness"]
        control_counts[state] = control_counts.get(state, 0) + 1
    evidence_counts = {EvidenceFreshness.FRESH.value: 0, EvidenceFreshness.STALE.value: 0}
    for record in evidence_rows:
        state = classify_freshness(evidence_observed_at(record), window_days=window)
        if state == EvidenceFreshness.UNTESTED.value:
            continue
        evidence_counts[state] = evidence_counts.get(state, 0) + 1
    return {
        "window_days": window,
        "states": [item.value for item in EvidenceFreshness],
        "fresh_controls": control_counts[EvidenceFreshness.FRESH.value],
        "stale_controls": control_counts[EvidenceFreshness.STALE.value],
        "untested_controls": control_counts[EvidenceFreshness.UNTESTED.value],
        "fresh_evidence": evidence_counts[EvidenceFreshness.FRESH.value],
        "stale_evidence": evidence_counts[EvidenceFreshness.STALE.value],
        "legal_compliance_claim": False,
    }
