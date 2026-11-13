from __future__ import annotations

import pytest

from threatsight_api.frameworks.catalog import CATALOG_ITEMS, CTRL002_SUGGESTIONS, FRAMEWORKS
from threatsight_api.frameworks.coverage import coverage_from_control_statuses


def test_catalog_covers_required_frameworks() -> None:
    keys = {item.key for item in FRAMEWORKS}
    assert keys == {"eu_ai_act", "gdpr", "nist_ai_rmf", "iso_42001", "owasp_genai", "mitre_atlas"}
    codes = {(item.framework_key, item.reference_code) for item in CATALOG_ITEMS}
    for pair in CTRL002_SUGGESTIONS:
        assert pair in codes
    assert all(item.locator.startswith("https://") for item in CATALOG_ITEMS)
    assert all("not a legal" in item.statement.lower() or "informational" in item.statement.lower() for item in CATALOG_ITEMS)


def test_unmapped_is_evidence_required() -> None:
    assert coverage_from_control_statuses([]) == "EVIDENCE_REQUIRED"


def test_gap_dominates_validated() -> None:
    assert coverage_from_control_statuses(["VALIDATED", "GAP_DETECTED"]) == "GAP_DETECTED"


def test_all_validated() -> None:
    assert coverage_from_control_statuses(["VALIDATED", "VALIDATED"]) == "VALIDATED"


def test_mixed_validated_is_partial() -> None:
    assert coverage_from_control_statuses(["VALIDATED", "EVIDENCE_REQUIRED"]) == "PARTIALLY_VALIDATED"


def test_human_review_dominates_validated() -> None:
    assert coverage_from_control_statuses(["VALIDATED", "HUMAN_REVIEW_REQUIRED"]) == "HUMAN_REVIEW_REQUIRED"


def test_coverage_rejects_compliant() -> None:
    with pytest.raises(ValueError, match="legal compliance"):
        coverage_from_control_statuses(["COMPLIANT"])
