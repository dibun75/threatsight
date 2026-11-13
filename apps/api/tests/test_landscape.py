from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

from sqlalchemy import text

from threatsight_api.landscape.priority import priority_reason
from threatsight_api.landscape.sanitize import plain
from threatsight_api.landscape.versioning import compare_version
from threatsight_api.main import app
from threatsight_api.persistence.session import SessionLocal

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}


def test_version_comparison_is_conservative() -> None:
    assert compare_version("semver", "1.2.3", "1.2.3") == "applicable"
    assert compare_version("semver", "1.2.4", ">=1.2.0,<1.3.0") == "applicable"
    assert compare_version("semver", "1.3.0", ">=1.2.0,<1.3.0") == "outside"
    assert compare_version("semver", "", "1.2.3") == "missing"
    assert compare_version("junos", "23.4R1-synth", "23.4R1-synth") == "unknown"
    assert compare_version("meraki", "29.1", "29.1") == "unknown"
    assert compare_version("cloud", "service", "service") == "unknown"
    assert compare_version("semver", "23.4R1", "23.4R1") == "unknown"


def test_priority_keeps_kev_and_epss_separate() -> None:
    assert priority_reason(version_result="applicable", kev=True, epss=0.1, vendor_severity="low", cvss=3, conflict=False)[0] == 1
    assert priority_reason(version_result="applicable", kev=False, epss=0.9, vendor_severity="low", cvss=3, conflict=False)[0] == 2
    assert priority_reason(version_result="missing", kev=False, epss=None, vendor_severity="high", cvss=None, conflict=False)[0] == 4


def test_advisory_text_is_plain() -> None:
    assert "<" not in plain("Fixture <script>alert(1)</script> title")


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_landscape_reads_are_bounded_and_do_not_infer_origin() -> None:
    with TestClient(app) as client:
        headers = {"X-Actor": "operator"}
        geography = client.get("/api/v1/landscape/geography?metric=attacker_origin", headers=headers)
        assert geography.status_code == 200
        body = geography.json()
        assert body["metric"] == "authority_jurisdiction"
        assert "attacker" in body["does_not_mean"]
        advisories = client.get("/api/v1/landscape/advisories?limit=100", headers=headers)
        assert advisories.status_code == 422
        page = client.get("/api/v1/landscape/advisories?limit=25", headers=headers)
        assert page.status_code == 200
        titles = " ".join(item["title"] for item in page.json()["items"])
        assert "<script>" not in titles
        detail = client.get("/api/v1/landscape/advisories/00000000-0000-4000-8000-000000002807", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["products"][0]["comparison"] == "unknown"
        missing = client.get(f"/api/v1/landscape/advisories/{uuid.uuid4()}", headers=headers)
        assert missing.status_code == 404
        sources = client.get("/api/v1/landscape/sources", headers=headers)
        assert sources.status_code == 200
        by_key = {item["key"]: item["maturity"] for item in sources.json()["items"]}
        assert by_key["juniper-psirt"] == "unsupported"
        assert by_key["cisco-openvuln"] == "credential_required"


def _reconciles(body: dict) -> None:
    assert body["stored_total"] == (
        body["live_verified_advisories"]
        + body["fixture_tested"]
        + body["credential_required"]
        + body["unsupported"]
        + body["unknown"]
        + body["excluded_withdrawn"]
    )


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_advisory_totals_keep_every_record_in_one_bucket() -> None:
    with TestClient(app) as client:
        before = client.get("/api/v1/landscape/summary").json()
        _reconciles(before)
        assert before["excluded_withdrawn"] >= 1
        assert before["credential_required"] >= 1
        assert before["unsupported"] >= 1
        withdrawn = client.get("/api/v1/landscape/advisories/00000000-0000-4000-8000-000000002809").json()
        assert withdrawn["withdrawn"] is True
        assert withdrawn["maturity"] == "fixture_tested"
        assert withdrawn["title"] == "Withdrawn fixture advisory"
        geography = client.get("/api/v1/landscape/geography?metric=authority_jurisdiction").json()
        assert before["stored_total"] != geography["included"] or geography["excluded"] == 0
        probe = str(uuid.uuid4())
        with SessionLocal() as db:
            db.execute(
                text(
                    """
                    INSERT INTO landscape_advisories (
                        id, source_key, external_id, title, summary, canonical_url, vendor,
                        vendor_advisory_id, cves, vendor_severity, vex_status, kev_listed,
                        exploitation_claim, withdrawn, freshness, conflict, maturity,
                        parser_version, evidence_hash, products, geography, limitations
                    ) VALUES (
                        :id, 'nvd-cve', 'unknown-maturity-probe', 'Unknown maturity probe', 'probe',
                        'https://example.com/probe', 'Example', 'unknown-maturity-probe', '[]'::jsonb,
                        'not_supplied', 'not_supplied', false, 'unknown', false, 'stale', false,
                        'not-a-maturity', 'landscape-v1', 'abc', '[]'::jsonb, '[]'::jsonb, '[]'::jsonb
                    )
                    """
                ),
                {"id": probe},
            )
            db.commit()
        after = client.get("/api/v1/landscape/summary").json()
        _reconciles(after)
        assert after["unknown"] == before["unknown"] + 1
        assert after["stale_included"] == before["stale_included"] + 1
        assert after["stored_total"] == before["stored_total"] + 1
        with SessionLocal() as db:
            db.execute(text("DELETE FROM landscape_advisories WHERE id = :id"), {"id": probe})
            db.commit()
        restored = client.get("/api/v1/landscape/summary").json()
        _reconciles(restored)
        assert restored["stored_total"] == before["stored_total"]
