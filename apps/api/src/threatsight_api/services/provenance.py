"""Dashboard data-origin transparency. Derived from persisted records; no new engines."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from threatsight_api.assurance.catalog import CTRL_002
from threatsight_api.assurance.engine import DEMO_ENVIRONMENT, DEMO_SYSTEM_NAME
from threatsight_api.domain.enums import CandidateReviewStatus, EvidenceType, RequirementSourceType
from threatsight_api.showcase.engine import ATTESTATION_REF, KNOWLEDGE_SYSTEM_NAME

LABELLED_SYSTEM_NAMES = frozenset({DEMO_SYSTEM_NAME, KNOWLEDGE_SYSTEM_NAME})


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def iso_stamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return as_utc(value).isoformat()


def latest_stamp(rows: Iterable[Any], *attr_names: str) -> str | None:
    stamps: list[datetime] = []
    for row in rows:
        for name in attr_names:
            value = getattr(row, name, None)
            if isinstance(value, datetime):
                stamps.append(as_utc(value))
    if not stamps:
        return None
    return iso_stamp(max(stamps))


def join_origins(*parts: str) -> str:
    return " / ".join(part for part in parts if part)


def provenance_block(
    *,
    data_origin: str,
    evidence_source: str,
    generated_by: str,
    last_updated: str | None,
    **extra: Any,
) -> dict:
    payload = {
        "data_origin": data_origin,
        "evidence_source": evidence_source,
        "generated_by": generated_by,
        "last_updated": last_updated,
        "legal_compliance_claim": False,
    }
    payload.update(extra)
    return payload


def is_labelled_system(item: Any) -> bool:
    name = getattr(item, "name", "")
    environment = getattr(item, "environment", "")
    return name in LABELLED_SYSTEM_NAMES and environment == DEMO_ENVIRONMENT


def systems_provenance(systems: list[Any]) -> dict:
    synthetic = [item for item in systems if is_labelled_system(item)]
    manual = [item for item in systems if not is_labelled_system(item)]
    origin = join_origins(
        "Synthetic demo inventory" if synthetic else "",
        "Manual registration" if manual else "",
    ) or "No records yet"
    return provenance_block(
        data_origin=origin,
        evidence_source="Inventory records in Postgres",
        generated_by="Operator registration and labelled showcase bootstrap",
        last_updated=latest_stamp(systems, "updated_at", "created_at"),
        synthetic_demo_inventory=bool(synthetic),
        labelled_synthetic=True,
        enterprise_inventory=False,
    )


def controls_provenance(controls: list[Any]) -> dict:
    seeded = any(getattr(item, "identifier", "") == CTRL_002 for item in controls)
    tested = sum(1 for item in controls if getattr(item, "latest_verdict", None))
    if not controls:
        origin = "No records yet"
    elif seeded:
        origin = "Governance catalog + seeded demo data"
    else:
        origin = "Governance catalog"
    return provenance_block(
        data_origin=origin,
        evidence_source="Control catalog records",
        generated_by="M1 governance catalog; CTRL-002 seeded when the demo is loaded",
        last_updated=latest_stamp(controls, "updated_at", "assurance_set_at", "created_at"),
        validation=f"{tested} technically tested",
        technically_tested=tested,
    )


def findings_provenance(findings: list[Any]) -> dict:
    with_evidence = sum(1 for item in findings if getattr(item, "evidence_id", None))
    origin = "M3 Assurance Engine" if findings else "No records yet"
    evidence_source = "Available" if with_evidence else "None recorded"
    return provenance_block(
        data_origin=origin,
        evidence_source=evidence_source,
        generated_by="CTRL-002 validation tests",
        last_updated=latest_stamp(findings, "updated_at", "created_at"),
        with_evidence=with_evidence,
    )


def evidence_provenance(records: list[Any]) -> dict:
    types = {getattr(item, "evidence_type", "") for item in records}
    labelled_attestation = any(getattr(item, "source_reference", None) == ATTESTATION_REF for item in records)
    origin_parts = []
    if labelled_attestation or EvidenceType.MANUAL.value in types:
        origin_parts.append("Manual records")
    if EvidenceType.OBSERVATION.value in types:
        origin_parts.append("Hashed observation envelopes")
    if EvidenceType.DOCUMENT.value in types:
        origin_parts.append("Document-linked records")
    origin = join_origins(*origin_parts) or ("Operator-submitted evidence" if records else "No records yet")
    generated = join_origins(
        "Labelled operator attestation" if labelled_attestation else "",
        "CTRL-002 executed runs" if EvidenceType.OBSERVATION.value in types else "",
        "Document intelligence" if EvidenceType.DOCUMENT.value in types else "",
    ) or "No evidence generated yet"
    source = join_origins(
        "Hashed CTRL-002 envelopes" if EvidenceType.OBSERVATION.value in types else "",
        "Labelled synthetic attestation" if labelled_attestation else "",
        "Manual evidence records" if EvidenceType.MANUAL.value in types and not labelled_attestation else "",
        "Uploaded document hashes" if EvidenceType.DOCUMENT.value in types else "",
    ) or ("Persisted evidence records" if records else "None recorded")
    return provenance_block(
        data_origin=origin,
        evidence_source=source,
        generated_by=generated,
        last_updated=latest_stamp(records, "updated_at", "collected_at", "created_at"),
        labelled_synthetic=labelled_attestation,
        count=len(records),
    )


def human_review_label(*, pending: int, approved: int) -> str:
    if pending == 0 and approved == 0:
        return "No candidates"
    if pending > 0 and approved == 0:
        return "Pending"
    if pending == 0 and approved > 0:
        return "Approved"
    return f"{approved} approved / {pending} pending"


def documents_provenance(documents: list[Any], requirements: list[Any], candidates: list[Any]) -> dict:
    pending = sum(1 for item in candidates if getattr(item, "review_status", "") == CandidateReviewStatus.PENDING.value)
    approved = sum(1 for item in candidates if getattr(item, "review_status", "") == CandidateReviewStatus.APPROVED.value)
    document_reqs = any(getattr(item, "source_type", "") == RequirementSourceType.DOCUMENT.value for item in requirements)
    other_reqs = any(getattr(item, "source_type", "") != RequirementSourceType.DOCUMENT.value for item in requirements)
    origin = join_origins(
        "Uploaded document" if documents else "",
        "Manual requirement records" if other_reqs else "",
        "Document-extracted requirements" if document_reqs and not documents else "",
    ) or "No records yet"
    extracted = bool(documents) or document_reqs
    return provenance_block(
        data_origin=origin,
        evidence_source="Document content hash and citations" if documents else "Requirement statements",
        generated_by="Document intelligence extraction with human review" if extracted else "Manual requirement entry",
        last_updated=latest_stamp([*documents, *requirements, *candidates], "updated_at", "created_at"),
        extraction_method="Document intelligence" if extracted else "Not applicable",
        human_review=human_review_label(pending=pending, approved=approved),
        pending_candidates=pending,
        approved_candidates=approved,
    )


def discovery_provenance(*, source_count: int, last_updated: str | None) -> dict:
    origin = "Authorized labelled demo site" if source_count else "No records yet"
    return provenance_block(
        data_origin=origin,
        evidence_source="Allow-listed fetch with page hash when a scan is confirmed",
        generated_by="M5 authorized discovery",
        last_updated=last_updated,
        unrestricted_crawl=False,
        enterprise_inventory=False,
    )


def frameworks_provenance(*, item_count: int, last_updated: str | None) -> dict:
    origin = "Curated informational catalog" if item_count else "No records yet"
    return provenance_block(
        data_origin=origin,
        evidence_source="Public locators; mappings are informational",
        generated_by="M6 catalog bootstrap",
        last_updated=last_updated,
        catalog_complete=False,
    )


def threats_provenance(*, technique_count: int, last_updated: str | None) -> dict:
    origin = "Curated incomplete intelligence catalog" if technique_count else "No records yet"
    return provenance_block(
        data_origin=origin,
        evidence_source="Public locators; mappings are informational",
        generated_by="M7 catalog bootstrap",
        last_updated=last_updated,
        catalog_complete=False,
        autonomous_attack=False,
    )


def freshness_provenance(*, last_updated: str | None) -> dict:
    return provenance_block(
        data_origin="Evidence timestamps on persisted records",
        evidence_source="Hashed envelopes and manual evidence dates",
        generated_by="Freshness window over real timestamps",
        last_updated=last_updated,
    )
