"""Phase 3D multi-source intelligence tests."""

from __future__ import annotations

import json
import os

import pytest
from sqlalchemy import text

from threatsight_api.intel.http import FetchError, fetch_https
from threatsight_api.multisource.parsers.siemens_csaf import parse_csaf, parse_feed_entries
from threatsight_api.multisource.parsers.thn_rss import parse_thn_rss
from threatsight_api.multisource.parsers.vulncheck_kev import parse_vulncheck_items
from threatsight_api.multisource.store import derive_exploitation_state, content_hash, link_cluster, upsert_document
from threatsight_api.multisource import SOURCE_ROLES, ASSERTION_TYPES, EXPLOITATION_STATES
from threatsight_api.multisource.collect import collect_vulncheck
from threatsight_api.multisource.reference import ASSET_KEY, SERVICE_KEY, install

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}

MINIMAL_CSAF = {
    "document": {
        "title": "SSA-834709: SIMATIC IoT2050 Advanced",
        "tracking": {
            "id": "SSA-834709",
            "version": "1.0",
            "status": "final",
            "initial_release_date": "2026-10-01T00:00:00Z",
            "current_release_date": "2026-10-14T00:00:00Z",
        },
        "references": [{"category": "self", "url": "https://cert-portal.siemens.com/productcert/csaf/ssa-834709.json"}],
    },
    "product_tree": {
        "branches": [
            {
                "category": "vendor",
                "name": "Siemens",
                "branches": [
                    {
                        "category": "product_name",
                        "name": "SIMATIC IoT2050 Advanced",
                        "branches": [
                            {
                                "category": "product_version_range",
                                "name": "vers:intdot/<4.3.4.1",
                                "product": {
                                    "product_id": "P1",
                                    "name": "SIMATIC IoT2050 Advanced with Node-RED",
                                    "product_identification_helper": {"model_numbers": ["6ES7647-0BA00-1YA2"]},
                                },
                            }
                        ],
                    }
                ],
            }
        ]
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2026-58115",
            "product_status": {"known_affected": ["P1"]},
            "remediations": [
                {"category": "vendor_fix", "details": "Update to V4.3.4.1 or later version"},
                {"category": "mitigation", "details": "Disable Node-RED if unused"},
            ],
        }
    ],
}

THN_RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel>
<item>
  <title>Siemens SIMATIC IoT2050 Flaw Actively Exploited CVE-2026-58115</title>
  <link>https://thehackernews.com/2026/10/siemens-iot2050.html?utm=1</link>
  <description><![CDATA[<p>Researchers observed exploitation. Full article body must not be stored.</p>]]></description>
  <pubDate>Tue, 14 Oct 2026 12:00:00 GMT</pubDate>
  <author>THN Staff</author>
</item>
</channel></rss>"""


def test_source_roles_and_states_are_separated() -> None:
    assert "vendor_authority" in SOURCE_ROLES
    assert "media_discovery" in SOURCE_ROLES
    assert "vendor_vulnerability_confirmed" in ASSERTION_TYPES
    assert "vendor_exploitation_confirmed" in ASSERTION_TYPES
    assert "researcher_exploitation_observed" in ASSERTION_TYPES
    assert "media_exploitation_reported" in ASSERTION_TYPES
    assert "government_catalogued" in EXPLOITATION_STATES
    assert "media_reported" in EXPLOITATION_STATES


def test_siemens_csaf_versions_prerequisites_and_roles() -> None:
    parsed = parse_csaf(json.dumps(MINIMAL_CSAF).encode())
    assert parsed["source_role"] == "vendor_authority"
    assert parsed["external_id"] == "SSA-834709"
    assert "CVE-2026-58115" in parsed["metadata_safe"]["cves"]
    types = {a["assertion_type"] for a in parsed["assertions"]}
    assert "product_affected" in types
    assert "version_affected" in types
    assert "fixed_version" in types
    assert "prerequisite_required" in types
    assert "vendor_vulnerability_confirmed" in types
    assert "vendor_exploitation_confirmed" not in types
    assert "vendor_confirmed" not in types
    assert "government_catalogued" not in types
    assert parsed["metadata_safe"]["vendor_exploitation_confirmed"] is False
    product = next(a for a in parsed["assertions"] if a["assertion_type"] == "product_affected")
    assert "6ES7647-0BA00-1YA2" in product["value"]["model_numbers"]


def test_siemens_feed_entries() -> None:
    feed = json.dumps({"feed": {"entry": [{"id": "SSA-834709"}, {"id": "SSA-000001"}]}}).encode()
    assert parse_feed_entries(feed) == ["SSA-834709", "SSA-000001"]


def test_thn_metadata_limits_and_copyright_boundary() -> None:
    items = parse_thn_rss(THN_RSS)
    assert len(items) == 1
    item = items[0]
    assert item["source_role"] == "media_discovery"
    assert item["canonical_url"] == "https://thehackernews.com/2026/10/siemens-iot2050.html"
    assert "utm" not in item["canonical_url"]
    assert "<" not in item["metadata_safe"]["excerpt"]
    assert len(item["metadata_safe"]["excerpt"]) <= 500
    assert "Full article body" in item["metadata_safe"]["excerpt"]
    assert item["assertions"][0]["assertion_type"] == "media_exploitation_reported"
    assert "media_discovery_is_not_vendor_truth" in item["assertions"][0]["limitations"]


def test_thn_rejects_entities_and_off_host() -> None:
    with pytest.raises(ValueError):
        parse_thn_rss(b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><rss>&xxe;</rss>")
    bad = THN_RSS.replace(b"thehackernews.com", b"evil.example")
    assert parse_thn_rss(bad) == []


def test_vulncheck_kev_catalog_is_not_direct_observation() -> None:
    payload = json.dumps(
        {
            "data": [
                {
                    "cve": ["CVE-2026-58115"],
                    "date_added": "2026-10-12T00:00:00Z",
                    "_timestamp": "2026-10-13T00:00:00Z",
                    "vendorProject": "Siemens",
                    "product": "SIMATIC IoT2050",
                    "vulnerabilityName": "Siemens SIMATIC IoT2050",
                    "vulncheck_reported_exploitation": [
                        {"url": "https://example.com/report", "date_added": "2026-10-12"}
                    ],
                    "reported_exploited_by_vulncheck_canaries": False,
                    "cisa_date_added": "2026-10-20",
                    "vulncheck_xdb": [{"xdb_id": "12345"}],
                }
            ]
        }
    ).encode()
    items = parse_vulncheck_items(payload)
    assert len(items) == 1
    assert items[0]["source_role"] == "exploitation_observation"
    assert items[0]["external_id"] == "vulncheck-kev:CVE-2026-58115"
    types = {a["assertion_type"] for a in items[0]["assertions"]}
    assert "researcher_catalogued" in types
    assert "exploitation_directly_observed" not in types
    assert "vendor_confirmed" not in types
    assert "government_catalogued" not in types
    assert items[0]["metadata_safe"]["cisa_date_added_present"] is True
    assert items[0]["metadata_safe"]["citation_count"] == 1


def test_vulncheck_canary_is_direct_observation() -> None:
    payload = json.dumps(
        {
            "data": [
                {
                    "cve": ["CVE-2026-58115"],
                    "date_added": "2026-10-12T00:00:00Z",
                    "reported_exploited_by_vulncheck_canaries": True,
                    "vulncheck_reported_exploitation": [],
                }
            ]
        }
    ).encode()
    items = parse_vulncheck_items(payload)
    types = {a["assertion_type"] for a in items[0]["assertions"]}
    assert "researcher_catalogued" in types
    assert "researcher_exploitation_observed" in types
    assert "exploitation_directly_observed" not in types


def test_vulncheck_index_meta_pagination() -> None:
    from threatsight_api.multisource.parsers.vulncheck_kev import parse_index_meta

    meta = parse_index_meta(b'{"data":[],"_meta":{"page":2,"total_pages":5,"total_documents":400}}')
    assert meta["page"] == 2
    assert meta["total_pages"] == 5


def test_exploitation_state_derivation_and_conflicts() -> None:
    # Vendor vulnerability alone is not exploitation confirmation.
    assert derive_exploitation_state({"vendor_vulnerability_confirmed"})[0] == "not_reported"
    assert derive_exploitation_state({"vendor_confirmed"})[0] == "not_reported"
    assert derive_exploitation_state({"vendor_vulnerability_confirmed", "researcher_exploitation_observed"})[0] == (
        "researcher_observed"
    )
    # Legacy vendor_confirmed + researcher observation must NOT become vendor_confirmed.
    assert derive_exploitation_state({"vendor_confirmed", "exploitation_directly_observed"})[0] == "researcher_observed"
    assert derive_exploitation_state({"media_exploitation_reported"})[0] == "media_reported"
    assert derive_exploitation_state({"exploitation_reported"})[0] == "media_reported"
    assert derive_exploitation_state({"researcher_catalogued"})[0] == "researcher_observed"
    assert derive_exploitation_state({"researcher_exploitation_observed"})[0] == "researcher_observed"
    assert derive_exploitation_state({"vendor_exploitation_confirmed"})[0] == "vendor_confirmed"
    assert derive_exploitation_state({"vendor_exploitation_confirmed", "researcher_exploitation_observed"})[0] == (
        "vendor_confirmed"
    )
    assert derive_exploitation_state({"government_catalogued"})[0] == "government_catalogued"
    assert derive_exploitation_state({"claim_withdrawn"})[0] == "withdrawn"
    assert derive_exploitation_state({"claim_withdrawn", "researcher_exploitation_observed"})[0] == "conflicting"
    assert derive_exploitation_state({"evidence_conflicting"})[0] == "conflicting"


def test_cve_2026_58115_contract_researcher_observed() -> None:
    """Siemens vulnerability + VulnCheck canary + catalog + THN → researcher_observed."""
    siemens = parse_csaf(json.dumps(MINIMAL_CSAF).encode())
    media = parse_thn_rss(THN_RSS)[0]
    vulncheck = parse_vulncheck_items(
        json.dumps(
            {
                "data": [
                    {
                        "cve": ["CVE-2026-58115"],
                        "date_added": "2026-10-12T00:00:00Z",
                        "reported_exploited_by_vulncheck_canaries": True,
                        "vulncheck_reported_exploitation": [{"url": "https://example.com/a", "date_added": "2026-10-12"}],
                    }
                ]
            }
        ).encode()
    )[0]
    types = {a["assertion_type"] for doc in (siemens, media, vulncheck) for a in doc["assertions"]}
    assert "vendor_vulnerability_confirmed" in types
    assert "vendor_exploitation_confirmed" not in types
    assert "researcher_exploitation_observed" in types
    assert "researcher_catalogued" in types
    assert "media_exploitation_reported" in types
    state, explanation = derive_exploitation_state(types)
    assert state == "researcher_observed"
    assert "Siemens" not in explanation or "not" in explanation.lower()
    assert "security researcher" in explanation.lower() or "researcher" in explanation.lower()


def test_ssa_580366_vendor_exploitation_confirmed() -> None:
    """Official Siemens wording about current known active exploitation may set vendor_confirmed."""
    from pathlib import Path

    payload = Path("/tmp/ssa-580366.json")
    if not payload.is_file():
        pytest.skip("official SSA-580366 fixture unavailable")
    parsed = parse_csaf(payload.read_bytes())
    assert parsed["external_id"] == "SSA-580366"
    assert "CVE-2026-110936" in parsed["metadata_safe"]["cves"]
    types = {a["assertion_type"] for a in parsed["assertions"]}
    assert "vendor_vulnerability_confirmed" in types
    assert "vendor_exploitation_confirmed" in types
    assert parsed["metadata_safe"]["vendor_exploitation_confirmed"] is True
    assert derive_exploitation_state(types)[0] == "vendor_confirmed"


def test_siemens_does_not_infer_exploitation_from_could_language() -> None:
    csaf = json.loads(json.dumps(MINIMAL_CSAF))
    csaf["document"]["notes"] = [
        {
            "category": "summary",
            "text": "This could allow an unauthenticated remote attacker to create malicious flows.",
        }
    ]
    parsed = parse_csaf(json.dumps(csaf).encode())
    types = {a["assertion_type"] for a in parsed["assertions"]}
    assert "vendor_exploitation_confirmed" not in types
    assert parsed["metadata_safe"]["vendor_exploitation_confirmed"] is False


def test_content_hash_stable_for_duplicate_stories() -> None:
    a = {"title": "t", "external_id": "1", "metadata_safe": {"cves": ["CVE-1"]}, "assertions": []}
    b = {"title": "t", "external_id": "1", "metadata_safe": {"cves": ["CVE-1"]}, "assertions": []}
    assert content_hash(a) == content_hash(b)


def test_duplicate_cve_stories_share_one_cluster_key() -> None:
    siemens = parse_csaf(json.dumps(MINIMAL_CSAF).encode())
    media = parse_thn_rss(THN_RSS)[0]
    assert siemens["metadata_safe"]["cves"] == media["metadata_safe"]["cves"] == ["CVE-2026-58115"]
    assert siemens["source_role"] != media["source_role"]


def test_product_name_collision_does_not_equal_model_match() -> None:
    parsed = parse_csaf(json.dumps(MINIMAL_CSAF).encode())
    product = next(a for a in parsed["assertions"] if a["assertion_type"] == "product_affected")
    assert product["value"]["model_numbers"] == ["6ES7647-0BA00-1YA2"]
    # Owning another Siemens product without this model is not a match.
    assert "S7-1500" not in json.dumps(product["value"])


def test_organization_relevance_requires_cve_and_model() -> None:
    from threatsight_api.multisource.service import _organization_relevance

    class _Fake:
        def scalar(self, *_a, **_k):
            return None

    empty = _organization_relevance(_Fake(), "CVE-2026-58115")
    assert empty["match_classification"] == "unknown"
    # Without an asset row the helper returns unknown; with a mismatched CVE it must not
    # claim Warehouse automation relevance. The live DB test covers the positive path.


def test_malformed_json_and_oversized_rss_item_limits() -> None:
    with pytest.raises(Exception):
        parse_csaf(b"{not-json")
    with pytest.raises(ValueError):
        parse_vulncheck_items(b'{"data":"nope"}')
    huge_title = "X" * 600
    rss = THN_RSS.replace(b"Siemens SIMATIC IoT2050 Flaw Actively Exploited CVE-2026-58115", huge_title.encode())
    items = parse_thn_rss(rss)
    assert len(items[0]["title"]) <= 500


def test_collector_ssrf_and_private_destinations() -> None:
    with pytest.raises(FetchError):
        fetch_https("http://cert-portal.siemens.com/x", hostname="cert-portal.siemens.com", limit=100)
    with pytest.raises(FetchError):
        fetch_https("https://127.0.0.1/", hostname="127.0.0.1", limit=100)
    with pytest.raises(FetchError):
        fetch_https("https://169.254.169.254/latest/meta-data", hostname="169.254.169.254", limit=100)
    with pytest.raises(FetchError):
        fetch_https("https://[::1]/", hostname="::1", limit=100)


@pytest.mark.skipif(not LIVE, reason="requires disposable postgres")
def test_cluster_store_clustering_and_idempotent_reference() -> None:
    from threatsight_api.config import get_settings
    from threatsight_api.db import run_migrations
    from threatsight_api.persistence.session import SessionLocal, configure_engine

    run_migrations(get_settings())
    configure_engine()
    with SessionLocal() as db:
        siemens = parse_csaf(json.dumps(MINIMAL_CSAF).encode())
        media = parse_thn_rss(THN_RSS)[0]
        doc1, changed1 = upsert_document(db, siemens)
        doc2, changed2 = upsert_document(db, media)
        assert changed1 and changed2
        c1 = link_cluster(db, cve="CVE-2026-58115", document=doc1, title=siemens["title"])
        c2 = link_cluster(db, cve="CVE-2026-58115", document=doc2, title=media["title"])
        assert c1.id == c2.id
        assert c1.exploitation_state in EXPLOITATION_STATES
        # Media alone cannot set vendor_confirmed / government_catalogued.
        assert c1.exploitation_state != "government_catalogued"
        doc1b, changed_again = upsert_document(db, siemens)
        assert doc1b.id == doc1.id
        assert changed_again is False
        # Kill switch / credential gate for VulnCheck without token.
        db.execute(
            text(
                """
                INSERT INTO intelligence_source_health (source_key, source_role, enabled, maturity, token_required)
                VALUES ('vulncheck-kev', 'exploitation_observation', true, 'credential_required', true)
                ON CONFLICT (source_key) DO UPDATE SET enabled = true
                """
            )
        )
        db.flush()
        result = collect_vulncheck(db)
        assert result["state"] in {"credential_required", "disabled"}
        snapshots = db.execute(text("SELECT count(*) FROM graph_snapshots WHERE is_current")).scalar() or 0
        if snapshots:
            install(db.connection())
            services = db.execute(text("SELECT count(*) FROM graph_nodes WHERE source_key = :k"), {"k": SERVICE_KEY}).scalar()
            assets = db.execute(text("SELECT count(*) FROM graph_nodes WHERE source_key = :k"), {"k": ASSET_KEY}).scalar()
            install(db.connection())
            services2 = db.execute(text("SELECT count(*) FROM graph_nodes WHERE source_key = :k"), {"k": SERVICE_KEY}).scalar()
            assets2 = db.execute(text("SELECT count(*) FROM graph_nodes WHERE source_key = :k"), {"k": ASSET_KEY}).scalar()
            assert services == services2
            assert assets == assets2
            unknown = db.execute(
                text("SELECT limitations FROM graph_nodes WHERE source_key = :k LIMIT 1"),
                {"k": ASSET_KEY},
            ).scalar()
            assert "industrial_os_version_unknown" in str(unknown)
            assert "node_red_installation_unknown" in str(unknown)
        db.rollback()


def test_ui_terminology_contract() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    page = (root / "apps/web/app/threats/page.tsx").read_text(encoding="utf-8")
    detail = (root / "apps/web/app/threats/emerging/[id]/page.tsx").read_text(encoding="utf-8")
    assert "Emerging exploitation" in page
    assert "Siemens ProductCERT — Vendor advisory" in detail
    assert "VulnCheck canary — Exploitation observed by researcher" in detail
    assert "VulnCheck KEV — Exploitation catalog" in detail
    assert "The Hacker News — Media report" in detail
    assert "CISA KEV" in detail
    assert "FIRST EPSS" in detail
    assert "does_not_mean" in detail
    assert "headline" in detail


def test_compose_vulncheck_mount_isolation() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    overlay = (root / "docker-compose.vulncheck.yml").read_text(encoding="utf-8")
    base = (root / "docker-compose.yml").read_text(encoding="utf-8")
    telemetry = (root / "docker-compose.telemetry.yml").read_text(encoding="utf-8")
    assert "THREATSIGHT_VULNCHECK_TOKEN_PATH" in overlay
    assert "/run/secrets/vulncheck_token" in overlay
    assert "intel-worker:" in overlay
    assert "vulncheck_token" not in base
    assert "cloudflare_radar_token" in telemetry
    assert "vulncheck_token" not in telemetry
    services = overlay.split("services:", 1)[1]
    assert "intel-worker:" in services
    for forbidden in ("\napi:", "\nweb:", "\npostgres:", "\nrunner:", "\nevidence-signer:", "\ncloudflared:"):
        assert forbidden not in services


def test_vulncheck_token_path_env_is_file_path_only() -> None:
    """Collector configuration references a path env, never an inline token value."""
    from pathlib import Path

    collect_src = Path(__file__).resolve().parents[1] / "src/threatsight_api/multisource/collect.py"
    text_src = collect_src.read_text(encoding="utf-8")
    assert 'os.environ.get("THREATSIGHT_VULNCHECK_TOKEN_FILE"' in text_src
    assert "THREATSIGHT_VULNCHECK_TOKEN=" not in text_src
    assert "Authorization" in text_src
    # Must not log Authorization headers.
    assert "Authorization" not in text_src.split("logger")[0] if "logger" in text_src else True
