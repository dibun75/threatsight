from __future__ import annotations

import os

import pytest
from sqlalchemy import text

from threatsight_api.config import get_settings
from threatsight_api.db import run_migrations
from threatsight_api.intel.collect import acquire, collect_source
from threatsight_api.intel.http import FetchError, fetch_https
from threatsight_api.intel.parsers import parse_epss_csv, parse_rss
from threatsight_api.persistence.session import SessionLocal, configure_engine

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
EPSS = b"#score_date:2026-10-31\ncve,epss,percentile\nCVE-2024-1001,0.20,0.40\n"


def test_epss_csv_rejects_formulas_and_keeps_dated_scores() -> None:
    with pytest.raises(FetchError) as caught:
        parse_epss_csv(b"#score_date:2026-10-31\n=1+1,0.1,0.1\n")
    assert caught.value.code == "csv_formula"
    score_date, rows = parse_epss_csv(b"#score_date:2026-10-31\ncve,epss,percentile\nCVE-2024-1001,0.2,0.4\n")
    assert score_date.isoformat() == "2026-10-31"
    official, _ = parse_epss_csv(b"#model_version:v2026.06.15,score_date:2026-10-31T12:00:27Z\ncve,epss,percentile\nCVE-2024-1001,0.2,0.4\n")
    assert official.isoformat() == "2026-10-31"
    assert rows == [("CVE-2024-1001", 0.2, 0.4)]


def test_rss_strips_markup_and_rejects_entities() -> None:
    items = parse_rss(b"<rss><channel><item><title>Alert &lt;script&gt;</title><link>https://aws.amazon.com/security/security-bulletins/</link></item></channel></rss>")
    assert "<" not in items[0]["title"]
    with pytest.raises(FetchError):
        parse_rss(b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><rss>&xxe;</rss>")


def test_fetch_refuses_private_and_off_host_targets() -> None:
    with pytest.raises(FetchError):
        fetch_https("http://epss.cyentia.com/epss_scores-current.csv.gz", hostname="epss.cyentia.com", limit=100)
    with pytest.raises(FetchError):
        fetch_https("https://127.0.0.1/secret", hostname="127.0.0.1", limit=100)


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_collection_is_idempotent_and_a_failure_keeps_the_cursor() -> None:
    run_migrations(get_settings())
    configure_engine()
    with SessionLocal() as db:
        first = collect_source(db, "first-epss", owner="test-a", payload=EPSS, meta={"etag": "fixture"})
        db.commit()
        assert first["status"] == "succeeded"
        second = collect_source(db, "first-epss", owner="test-b", payload=EPSS, meta={"etag": "fixture"})
        db.commit()
        assert second["status"] == "succeeded"
        count = db.execute(text("SELECT count(*) FROM epss_observations WHERE cve = 'CVE-2024-1001'")).scalar()
        assert count == 1
        held = acquire(db, "aws-bulletins", "worker-1")
        assert held is True
        assert acquire(db, "aws-bulletins", "worker-2") is False
        db.rollback()
        failed = collect_source(db, "nvd-cve", owner="test-c", payload=b"not-json")
        db.commit()
        assert failed["status"] == "failed"
        cursor = db.execute(text("SELECT cursor FROM landscape_schedules WHERE source_key = 'nvd-cve'")).scalar()
        assert cursor is None
