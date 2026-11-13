from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from threatsight_api.persistence.base import Base
from threatsight_api.radar.fetch import SourceFetchError, source_url
from threatsight_api.radar.parsers import parse_cisa_kev, parse_first_epss, parse_nsm_rss
from threatsight_api.radar.relevance import score_relevance


def test_normalized_schema_is_registered() -> None:
    expected = {
        "workspaces",
        "workspace_memberships",
        "organization_profiles",
        "threat_sources",
        "threat_events",
        "vulnerability_signals",
        "threat_relevance",
    }
    assert expected.issubset(Base.metadata.tables)


def test_cisa_kev_parser_normalizes_provenance() -> None:
    payload = json.dumps(
        {
            "catalogVersion": "2026.10.30",
            "dateReleased": "2026-10-30T10:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-12345",
                    "vendorProject": "Cisco",
                    "product": "Secure Firewall",
                    "dateAdded": "2026-10-29",
                    "shortDescription": "Actively exploited issue.",
                    "requiredAction": "Apply mitigations.",
                    "dueDate": "2026-11-10",
                    "knownRansomwareCampaignUse": "Known",
                }
            ],
        }
    ).encode()
    events = parse_cisa_kev(payload)
    assert len(events) == 1
    assert events[0].external_id == "CVE-2026-12345"
    assert events[0].event_type == "vulnerability"
    assert events[0].exploitation_status == "known_exploited"
    assert events[0].vendors == ["Cisco"]
    assert events[0].cves == ["CVE-2026-12345"]
    assert events[0].attributes["catalog_version"] == "2026.10.30"


def test_nsm_rss_and_epss_parsers() -> None:
    rss = b"""<?xml version="1.0"?><rss><channel><item>
      <title>Critical VPN issue CVE-2026-12345</title>
      <link>https://nsm.no/fagomrader/digital-sikkerhet/test</link>
      <guid>nsm-test-1</guid>
      <description><![CDATA[<p>Patch the affected VPN.</p>]]></description>
      <pubDate>Thu, 29 Oct 2026 10:00:00 +0100</pubDate>
    </item></channel></rss>"""
    events = parse_nsm_rss(rss)
    assert events[0].countries == ["NO"]
    assert events[0].cves == ["CVE-2026-12345"]
    assert "<p>" not in events[0].summary

    epss = parse_first_epss(
        b'{"data":[{"cve":"CVE-2026-12345","epss":"0.72","percentile":"0.98","date":"2026-10-29"}]}'
    )
    assert epss["CVE-2026-12345"][0] == 0.72


def test_source_urls_are_fixed_and_batches_bounded() -> None:
    assert source_url("cisa-kev").startswith("https://www.cisa.gov/")
    assert "CVE-2026-12345" in source_url("first-epss", ["CVE-2026-12345"])
    with pytest.raises(SourceFetchError):
        source_url("unknown")
    with pytest.raises(SourceFetchError):
        source_url("first-epss", [f"CVE-2026-{index:04d}" for index in range(101)])


def test_relevance_is_deterministic_and_explainable() -> None:
    profile = SimpleNamespace(
        countries=["NO"],
        sectors=["retail"],
        vendors=["Cisco"],
        products=[],
        technologies=["vpn"],
    )
    event = SimpleNamespace(
        countries=["NO"],
        sectors=[],
        vendors=["Cisco"],
        products=["Secure Firewall"],
        technologies=["vpn"],
        event_type="vulnerability",
        exploitation_status="known_exploited",
    )
    result = score_relevance(profile, event, [0.72])
    assert result.score == 95
    assert result.level == "critical"
    assert result.matches == {"countries": ["NO"], "vendors": ["Cisco"], "technologies": ["vpn"]}
    assert any("active exploitation" in reason for reason in result.reasons)
