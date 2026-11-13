from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from threatsight_api.services.dashboard import ASSURANCE_KEYS, count_enum
from threatsight_api.services.provenance import (
    controls_provenance,
    discovery_provenance,
    documents_provenance,
    evidence_provenance,
    findings_provenance,
    frameworks_provenance,
    systems_provenance,
)

STAMP = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def test_count_enum_fills_zeros_and_ignores_unknown() -> None:
    counts = count_enum(["VALIDATED", "GAP_DETECTED", "mystery"], ASSURANCE_KEYS)
    assert counts["VALIDATED"] == 1
    assert counts["GAP_DETECTED"] == 1
    assert counts["EVIDENCE_REQUIRED"] == 0
    assert "mystery" not in counts
    assert "COMPLIANT" not in counts


def test_systems_origin_synthetic_and_manual() -> None:
    rows = [
        SimpleNamespace(name="Order support demo", environment="lab", updated_at=STAMP, created_at=STAMP),
        SimpleNamespace(name="Finance bot", environment="prod", updated_at=STAMP, created_at=STAMP),
    ]
    payload = systems_provenance(rows)
    assert payload["data_origin"] == "Synthetic demo inventory / Manual registration"
    assert payload["legal_compliance_claim"] is False
    assert payload["enterprise_inventory"] is False
    assert payload["last_updated"]
    assert "COMPLIANT" not in str(payload)


def test_systems_origin_empty_is_honest() -> None:
    payload = systems_provenance([])
    assert payload["data_origin"] == "No records yet"
    assert payload["last_updated"] is None
    assert payload["legal_compliance_claim"] is False


def test_findings_provenance_from_assurance_engine() -> None:
    payload = findings_provenance(
        [SimpleNamespace(evidence_id="env-1", updated_at=STAMP, created_at=STAMP, status="open")]
    )
    assert payload["data_origin"] == "M3 Assurance Engine"
    assert payload["generated_by"] == "CTRL-002 validation tests"
    assert payload["evidence_source"] == "Available"
    assert payload["legal_compliance_claim"] is False
    assert "COMPLIANT" not in str(payload)


def test_controls_provenance_seeded_and_tested() -> None:
    payload = controls_provenance(
        [
            SimpleNamespace(identifier="CTRL-002", latest_verdict="FAIL", updated_at=STAMP, assurance_set_at=STAMP, created_at=STAMP),
            SimpleNamespace(identifier="CTRL-001", latest_verdict=None, updated_at=STAMP, assurance_set_at=None, created_at=STAMP),
        ]
    )
    assert payload["data_origin"] == "Governance catalog + seeded demo data"
    assert payload["validation"] == "1 technically tested"
    assert payload["legal_compliance_claim"] is False


def test_evidence_and_documents_provenance() -> None:
    evidence = evidence_provenance(
        [
            SimpleNamespace(
                evidence_type="manual",
                source_reference="m10-labelled-attestation",
                updated_at=STAMP,
                collected_at=STAMP,
                created_at=STAMP,
            )
        ]
    )
    assert evidence["legal_compliance_claim"] is False
    assert "labelled" in evidence["generated_by"].lower() or "attestation" in evidence["generated_by"].lower()
    documents = documents_provenance(
        [SimpleNamespace(updated_at=STAMP, created_at=STAMP)],
        [SimpleNamespace(source_type="document", updated_at=STAMP, created_at=STAMP)],
        [SimpleNamespace(review_status="pending", updated_at=STAMP, created_at=STAMP)],
    )
    assert documents["data_origin"] == "Uploaded document"
    assert documents["extraction_method"] == "Document intelligence"
    assert documents["human_review"] == "Pending"
    assert documents["legal_compliance_claim"] is False


def test_discovery_and_frameworks_never_claim_enterprise_inventory() -> None:
    discovery = discovery_provenance(source_count=1, last_updated=STAMP.isoformat())
    assert discovery["enterprise_inventory"] is False
    assert discovery["unrestricted_crawl"] is False
    assert discovery["data_origin"] == "Authorized labelled demo site"
    assert discovery["legal_compliance_claim"] is False
    frameworks = frameworks_provenance(item_count=4, last_updated=STAMP.isoformat())
    assert frameworks["catalog_complete"] is False
    assert "informational" in frameworks["evidence_source"].lower()
    assert "COMPLIANT" not in str(discovery) + str(frameworks)
