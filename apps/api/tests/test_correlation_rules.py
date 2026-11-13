from __future__ import annotations

from datetime import UTC, datetime

from threatsight_api.correlation.fixture import reference_aliases, reference_events
from threatsight_api.correlation.rules import correlate
from threatsight_api.correlation.versions import parse_range, parse_version
from threatsight_api.graph.fixture import load_fixture
from threatsight_api.graph.project import project

FORBIDDEN = ("safe", "secure", "compliant", "compromised", "exploitable", "breached", "protected", "reachable", "attacker")


def _outcome():
    bundle = load_fixture("correlation")
    built = project(bundle.records, now=datetime(2026, 10, 31, tzinfo=UTC), memberships=bundle.memberships, actor="fixture")
    return correlate(reference_events(), built.nodes, built.edges, built.memberships, reference_aliases())


def _matches(outcome, cve, asset_part):
    return [item for item in outcome["results"] if item["cve"] == cve and asset_part in item["asset_key"]]


def test_reference_correlation_is_deterministic_and_cautious() -> None:
    first = _outcome()
    second = _outcome()
    assert first == second
    for item in first["results"]:
        text = f" {item['state']} {item['explanation']} "
        for word in FORBIDDEN:
            assert f" {word} " not in text
        assert "<" not in item["explanation"]
        assert "payload" not in item
    exact = _matches(first, "CVE-2024-1001", "exact-widget")
    assert exact and exact[0]["state"] == "confirmed_identifier_match"
    assert any("customer-ordering" in item["source_key"] for item in exact[0]["services"])
    assert exact[0]["geography"]["authority_jurisdictions"] == ["US"]
    assert exact[0]["geography"]["target_countries"] == ["SE"]
    assert "attacker" not in exact[0]["geography"]
    ranged = _matches(first, "CVE-2024-1002", "range-widget")
    assert ranged and ranged[0]["state"] == "version_supported_candidate"
    assert ranged[0]["freshness"] == "stale" or "stale_input" in ranged[0]["limitations"]
    alias = _matches(first, "CVE-2024-1003", "alias-widget")
    assert alias and alias[0]["rule_id"] == "vendor-product-alias-v1"
    firmware = _matches(first, "CVE-2024-2001", "meraki-ap")
    assert firmware and firmware[0]["state"] == "version_supported_candidate"
    assert any("privileged-administration" in item["source_key"] for item in firmware[0]["services"])
    junos = _matches(first, "CVE-2024-3001", "junos")
    assert junos and junos[0]["state"] == "unknown"
    assert "unsupported_version" in junos[0]["missing_facts"]
    assert any("remote-access" in item["source_key"] for item in junos[0]["services"])
    missing = _matches(first, "CVE-2024-1002", "missing-widget")
    assert missing and missing[0]["state"] == "possible_match"
    assert "missing_version" in missing[0]["missing_facts"]
    conflict = _matches(first, "CVE-2024-4001", "conflict-widget")
    assert len(conflict) == 1
    assert conflict[0]["state"] == "conflicting"
    duplicate = _matches(first, "CVE-2024-5001", "exact-widget")
    assert len(duplicate) == 1
    assert duplicate[0]["source_count"] == 2
    outside = _matches(first, "CVE-2024-6001", "range-widget")
    assert outside and outside[0]["state"] == "not_applicable_by_evidence"
    assert not _matches(first, "CVE-2024-7002", "unrelated")
    assert not any("unrelated" in item["asset_key"] for item in first["results"])
    cloud = _matches(first, "CVE-2024-7001", "synthetic-web")
    assert cloud and cloud[0]["state"] == "possible_match"
    assert not _matches(first, "CVE-2024-7002", "subscription")
    purl = _matches(first, "CVE-2024-8001", "purl-helper")
    assert purl and purl[0]["rule_id"] == "software-identifier-v1"
    kev = exact[0]
    assert "kev_is_not_customer_attack" in kev["limitations"] or any("kev_is_not_customer_attack" in item["limitations"] for item in exact)


def test_versions_reject_unsupported_and_adversarial_input() -> None:
    assert parse_version("1.2.3") == (1, 2, 3)
    assert parse_version("23.4R1-synth") is None
    assert parse_version("1" * 80) is None
    assert parse_version("1." * 30) is None
    assert parse_range(">=1.2.0,<1.3.0")
    assert parse_range(">=1.0.0") 
    assert parse_range(">=1.0.0") is not None
    from threatsight_api.correlation.versions import range_is_complete
    assert range_is_complete(parse_range(">=1.0.0")) is False
    assert range_is_complete(parse_range(">=1.2.0,<1.3.0")) is True
    huge = [{"event_id": "x", "cves": ["CVE-2024-1001"], "cpes": [], "vendors": ["acme"], "products": ["widget"], "version_ranges": [], "purls": [], "cloud_service": "", "cloud_scope": "", "exploitation_status": "unknown", "epss_score": None, "epss_date": None, "freshness": "fresh", "authority_jurisdictions": [], "target_countries": [], "victim_countries": [], "infrastructure_countries": [], "prevalence_countries": [], "source_key": "synthetic", "provenance": {}, "cluster_key": None}]
    node = {"source_key": "asset", "node_type": "device", "connector_key": "synthetic.fixture", "evidence_mode": "configured", "freshness": "fresh", "maturity": "fixture_tested", "attributes": {"vendor": "acme", "product": "widget", "version": "1." * 5000, "name": "<script>alert(1)</script>"}}
    outcome = correlate(huge, [node], [], [], [])
    assert outcome["results"]
    assert outcome["results"][0]["state"] == "unknown"
    assert "<script>" not in outcome["results"][0]["explanation"]


def test_cycle_and_comparison_limit(monkeypatch) -> None:
    monkeypatch.setattr("threatsight_api.correlation.rules.MAX_COMPARISONS", 1)
    outcome = _outcome()
    assert "comparison_limit" in outcome["limitations"]
    left = {"source_key": "a", "node_type": "device", "connector_key": "synthetic.fixture", "evidence_mode": "configured", "freshness": "fresh", "maturity": "fixture_tested", "attributes": {"vendor": "acme", "product": "widget", "version": "1.2.3", "cpe": "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"}}
    right = {"source_key": "b", "node_type": "device", "connector_key": "synthetic.fixture", "evidence_mode": "configured", "freshness": "fresh", "maturity": "fixture_tested", "attributes": {}}
    service = {"source_key": "svc", "node_type": "business_service", "connector_key": "synthetic.fixture", "evidence_mode": "manual", "freshness": "fresh", "maturity": "synthetic", "attributes": {}}
    edges = [
        {"source_key": "e1", "edge_type": "depends_on", "from_key": "a", "to_key": "b", "evidence_mode": "configured"},
        {"source_key": "e2", "edge_type": "depends_on", "from_key": "b", "to_key": "a", "evidence_mode": "configured"},
        {"source_key": "e3", "edge_type": "depends_on", "from_key": "b", "to_key": "svc", "evidence_mode": "manual"},
    ]
    event = reference_events()[0]
    monkeypatch.setattr("threatsight_api.correlation.rules.MAX_COMPARISONS", 5000)
    cycled = correlate([event], [left, right, service], edges, [], [])
    assert cycled["results"]
    assert "cycle_terminated" in cycled["results"][0]["limitations"]
