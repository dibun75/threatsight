from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from threatsight_api.intel.http import FetchError, fetch_https, gunzip_bounded, sha256
from threatsight_api.intel.parsers import parse_epss_csv, parse_nvd, parse_rss
from threatsight_api.landscape.sanitize import plain

PARSER_VERSION = "landscape-live-v1"
LEASE_MINUTES = 15

SOURCES = {
    "first-epss": {
        "url": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        "host": "epss.empiricalsecurity.com",
        "kind": "epss",
        "limit": 4_000_000,
    },
    "nvd-cve": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "host": "services.nvd.nist.gov",
        "kind": "nvd",
        "limit": 1_000_000,
    },
    "aws-bulletins": {
        "url": "https://aws.amazon.com/security/security-bulletins/rss/feed/",
        "host": "aws.amazon.com",
        "kind": "rss",
        "limit": 1_000_000,
    },
    "fortinet-psirt": {
        "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
        "host": "filestore.fortinet.com",
        "kind": "rss",
        "limit": 1_000_000,
    },
    "paloalto-advisory": {
        "url": "https://security.paloaltonetworks.com/rss.xml",
        "host": "security.paloaltonetworks.com",
        "kind": "rss",
        "limit": 1_000_000,
    },
}


def health_for(row: dict) -> str:
    if row["kill_switch"] or not row["enabled"]:
        return "disabled"
    if row["maturity"] == "credential_required":
        return "credential_required"
    if row["maturity"] == "unsupported":
        return "unsupported"
    if row["maturity"] == "fixture_tested" and row["source_key"] not in SOURCES:
        return "fixture_only"
    if row.get("lease_expires_at") and row["lease_expires_at"] > datetime.now(UTC):
        return "running"
    if row["last_error_code"] == "rate_limited":
        return "rate_limited"
    if row["consecutive_failures"] >= 3:
        return "failed"
    if row["last_success_at"] is None:
        return "due"
    age = datetime.now(UTC) - row["last_success_at"]
    if age > timedelta(hours=int(row["freshness_hours"])):
        return "stale"
    if row["consecutive_failures"]:
        return "degraded"
    return "healthy"


def acquire(db: Session, source_key: str, owner: str) -> bool:
    updated = db.execute(
        text(
            """
            UPDATE landscape_schedules
               SET lease_owner = :owner,
                   lease_expires_at = now() + make_interval(mins => :minutes)
             WHERE source_key = :source_key
               AND enabled
               AND NOT kill_switch
               AND (lease_expires_at IS NULL OR lease_expires_at < now())
            """
        ),
        {"owner": owner, "minutes": LEASE_MINUTES, "source_key": source_key},
    )
    return updated.rowcount == 1


def _finish(db: Session, source_key: str, *, ok: bool, error: str | None, cursor: str | None, etag: str | None, modified: str | None, counts: dict, checksum: str) -> None:
    db.execute(
        text(
            """
            UPDATE landscape_schedules
               SET lease_owner = NULL,
                   lease_expires_at = NULL,
                   cursor = COALESCE(:cursor, cursor),
                   etag = COALESCE(:etag, etag),
                   last_modified = COALESCE(:modified, last_modified),
                   last_success_at = CASE WHEN :ok THEN now() ELSE last_success_at END,
                   consecutive_failures = CASE WHEN :ok THEN 0 ELSE consecutive_failures + 1 END,
                   last_error_code = :error,
                   next_attempt_at = now() + make_interval(mins => interval_minutes)
             WHERE source_key = :source_key
            """
        ),
        {
            "source_key": source_key,
            "ok": ok,
            "error": error,
            "cursor": cursor,
            "etag": etag,
            "modified": modified,
        },
    )
    db.execute(
        text(
            """
            INSERT INTO landscape_collection_runs (
                id, source_key, status, started_at, completed_at, cursor_after, etag,
                records_received, records_inserted, records_updated, records_withdrawn,
                records_rejected, error_code, response_sha256, parser_version
            ) VALUES (
                :id, :source_key, :status, now(), now(), :cursor, :etag,
                :received, :inserted, :updated, :withdrawn, :rejected, :error, :checksum, :parser
            )
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "source_key": source_key,
            "status": "succeeded" if ok else "failed",
            "cursor": cursor,
            "etag": etag,
            "received": counts.get("received", 0),
            "inserted": counts.get("inserted", 0),
            "updated": counts.get("updated", 0),
            "withdrawn": counts.get("withdrawn", 0),
            "rejected": counts.get("rejected", 0),
            "error": error,
            "checksum": checksum,
            "parser": PARSER_VERSION,
        },
    )
    if ok and source_key in SOURCES:
        db.execute(
            text("UPDATE threat_sources SET maturity = 'live_verified', last_status = 'ok', last_success_at = now() WHERE key = :key"),
            {"key": source_key},
        )


def _store_advisories(db: Session, source_key: str, items: list[dict], maturity: str) -> dict:
    inserted = updated = withdrawn = 0
    seen: set[str] = set()
    for item in items:
        if item["external_id"] in seen:
            continue
        seen.add(item["external_id"])
        existing = db.execute(
            text("SELECT id, withdrawn FROM landscape_advisories WHERE source_key = :source AND external_id = :external"),
            {"source": source_key, "external": item["external_id"][:200]},
        ).first()
        payload = {
            "source": source_key,
            "external": item["external_id"][:200],
            "title": plain(item["title"], 300),
            "summary": plain(item.get("summary") or item["title"], 1000),
            "url": item["url"],
            "cves": json.dumps(item.get("cves") or []),
            "withdrawn": bool(item.get("withdrawn")),
            "maturity": maturity,
            "vendor": plain(item.get("vendor") or source_key, 80),
        }
        if existing is None:
            db.execute(
                text(
                    """
                    INSERT INTO landscape_advisories (
                        id, source_key, external_id, title, summary, canonical_url, vendor,
                        vendor_advisory_id, cves, vendor_severity, vex_status, kev_listed,
                        exploitation_claim, withdrawn, freshness, conflict, maturity,
                        parser_version, evidence_hash, products, geography, limitations
                    ) VALUES (
                        :id, :source, :external, :title, :summary, :url, :vendor,
                        :external, CAST(:cves AS jsonb), 'not_supplied', 'not_supplied', false,
                        'unknown', :withdrawn, CASE WHEN :withdrawn THEN 'withdrawn' ELSE 'current' END, false, :maturity,
                        :parser, :digest, '[]'::jsonb, '[]'::jsonb,
                        '["initial_horizon","not_customer_inventory","not_attacker_origin"]'::jsonb
                    )
                    """
                ),
                {**payload, "id": str(uuid.uuid4()), "parser": PARSER_VERSION, "digest": sha256(payload["title"].encode())},
            )
            inserted += 1
        else:
            db.execute(
                text(
                    """
                    UPDATE landscape_advisories
                       SET title = :title, summary = :summary, canonical_url = :url, cves = CAST(:cves AS jsonb),
                           withdrawn = :withdrawn, maturity = :maturity, parser_version = :parser
                     WHERE id = :id
                    """
                ),
                {**payload, "id": existing[0], "parser": PARSER_VERSION},
            )
            updated += 1
            if item.get("withdrawn") and not existing[1]:
                withdrawn += 1
    return {"received": len(items), "inserted": inserted, "updated": updated, "withdrawn": withdrawn, "rejected": 0}


def _store_epss(db: Session, score_date, rows: list[tuple[str, float, float]]) -> dict:
    inserted = 0
    for offset in range(0, len(rows), 1000):
        batch = rows[offset:offset + 1000]
        db.execute(
            text(
                """
                INSERT INTO epss_observations (cve, score_date, score, percentile)
                SELECT * FROM unnest(CAST(:cves AS text[]), CAST(:dates AS date[]), CAST(:scores AS float8[]), CAST(:percentiles AS float8[]))
                ON CONFLICT (cve, score_date) DO UPDATE
                  SET score = EXCLUDED.score, percentile = EXCLUDED.percentile
                """
            ),
            {
                "cves": [row[0] for row in batch],
                "dates": [score_date for _ in batch],
                "scores": [row[1] for row in batch],
                "percentiles": [row[2] for row in batch],
            },
        )
        inserted += len(batch)
    db.execute(
        text(
            """
            UPDATE landscape_advisories AS advisory
               SET epss_score = observation.score,
                   epss_percentile = observation.percentile
              FROM epss_observations AS observation
             WHERE observation.score_date = :score_date
               AND advisory.cves ? observation.cve
            """
        ),
        {"score_date": score_date},
    )
    return {"received": len(rows), "inserted": inserted, "updated": 0, "withdrawn": 0, "rejected": 0}


def collect_source(db: Session, source_key: str, *, owner: str, payload: bytes | None = None, meta: dict | None = None) -> dict:
    if source_key not in SOURCES:
        raise FetchError("unsupported_source")
    if not acquire(db, source_key, owner):
        return {"status": "lease_held"}
    spec = SOURCES[source_key]
    schedule = db.execute(text("SELECT etag, cursor FROM landscape_schedules WHERE source_key = :key"), {"key": source_key}).one()
    try:
        if payload is None:
            url = spec["url"]
            if spec["kind"] == "nvd":
                end = datetime.now(UTC).replace(microsecond=0)
                start = end - timedelta(days=7)
                url = (
                    f"{spec['url']}?resultsPerPage=5&startIndex=0"
                    f"&lastModStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
                    f"&lastModEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
                )
            status, headers, body = fetch_https(
                url,
                hostname=spec["host"],
                limit=spec["limit"],
                etag=schedule.etag or None,
                timeout=120 if spec["kind"] == "epss" else 30,
            )
            if status == 304:
                counts = {"received": 0, "inserted": 0, "updated": 0, "withdrawn": 0, "rejected": 0}
                _finish(db, source_key, ok=True, error=None, cursor=schedule.cursor, etag=schedule.etag, modified=None, counts=counts, checksum="")
                return {"status": "not_modified", **counts}
        else:
            headers = meta or {}
            body = payload
        checksum = sha256(body)
        if spec["kind"] == "epss":
            decoded = gunzip_bounded(body, 40_000_000) if body.startswith(b"\x1f\x8b") else body
            score_date, rows = parse_epss_csv(decoded)
            counts = _store_epss(db, score_date, rows)
            cursor = score_date.isoformat()
        elif spec["kind"] == "nvd":
            counts = _store_advisories(db, source_key, parse_nvd(body), "live_verified")
            cursor = datetime.now(UTC).date().isoformat()
        else:
            counts = _store_advisories(db, source_key, parse_rss(body), "live_verified")
            cursor = checksum[:16]
        _finish(
            db,
            source_key,
            ok=True,
            error=None,
            cursor=cursor,
            etag=headers.get("etag") or None,
            modified=headers.get("last_modified") or None,
            counts=counts,
            checksum=checksum,
        )
        return {"status": "succeeded", **counts}
    except FetchError as exc:
        db.rollback()
        acquire(db, source_key, owner)
        _finish(db, source_key, ok=False, error=exc.code, cursor=None, etag=None, modified=None, counts={}, checksum="")
        return {"status": "failed", "error": exc.code}
