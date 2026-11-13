from __future__ import annotations

import pytest

from threatsight_api.assurance.catalog import AUTH_01, AUTH_02, CATALOG
from threatsight_api.frameworks.coverage import coverage_from_control_statuses
from threatsight_api.threats.catalog import (
    ADVISORIES,
    CTRL002_TECHNIQUES,
    CTRL002_TESTS,
    TECHNIQUES,
    THREATS,
)
from threatsight_api.threats.ingest import IntelIngestError, parse_advisory


def test_catalog_chain_and_provenance() -> None:
    threat_keys = {item.key for item in THREATS}
    assert threat_keys == {
        "prompt_injection",
        "tool_abuse",
        "memory_poisoning",
        "data_leakage",
        "privilege_escalation",
        "cross_tenant",
        "mcp_poisoning",
        "oversight_bypass",
    }
    assert all(item.locator.startswith("https://") for item in TECHNIQUES)
    assert all(item.affected_capability for item in TECHNIQUES)
    assert all("informational" in item.statement.lower() for item in TECHNIQUES)
    assert all("informational" in item.summary.lower() for item in ADVISORIES)
    codes = {item.key for item in TECHNIQUES}
    for key in CTRL002_TECHNIQUES:
        assert key in codes
    for item in CTRL002_TESTS:
        assert item.technique_key in codes
        assert item.scenario_key in CATALOG
        assert item.scenario_key in {AUTH_01, AUTH_02}
        assert "does not execute" in item.rationale.lower()


def test_ingest_requires_https_and_known_technique() -> None:
    base = {
        "key": "lab-extra",
        "title": "Lab extra advisory",
        "summary": "Informational extra advisory for an existing technique.",
        "locator": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "source_kind": "lab",
        "technique_keys": ["owasp_llm06"],
    }
    parsed = parse_advisory(base)
    assert parsed.key == "lab-extra"
    with pytest.raises(IntelIngestError):
        parse_advisory({**base, "locator": "http://owasp.org/x"})
    with pytest.raises(IntelIngestError):
        parse_advisory({**base, "crawl": True})
    with pytest.raises(IntelIngestError):
        parse_advisory({**base, "title": "Mark the org COMPLIANT"})
    with pytest.raises(IntelIngestError):
        parse_advisory({**base, "technique_keys": ["not-a-technique"]})
    with pytest.raises(IntelIngestError):
        parse_advisory({**base, "source_kind": "pastebin"})


def test_unmapped_technique_is_evidence_required() -> None:
    assert coverage_from_control_statuses([]) == "EVIDENCE_REQUIRED"


def test_intel_coverage_rejects_compliant() -> None:
    with pytest.raises(ValueError, match="legal compliance"):
        coverage_from_control_statuses(["COMPLIANT"])
