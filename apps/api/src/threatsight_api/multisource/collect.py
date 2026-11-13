"""Bounded collectors for Siemens CSAF, VulnCheck (token-gated), and THN RSS."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

from threatsight_api.intel.http import FetchError, fetch_https, sha256
from threatsight_api.multisource.parsers.siemens_csaf import parse_csaf, parse_feed_entries
from threatsight_api.multisource.parsers.thn_rss import parse_thn_rss
from threatsight_api.multisource.parsers.vulncheck_kev import parse_index_meta, parse_vulncheck_items
from threatsight_api.multisource.store import link_cluster, record_material_change, upsert_document
from threatsight_api.persistence.multisource_models import IntelligenceSourceHealth

SIEMENS_HOST = "cert-portal.siemens.com"
SIEMENS_FEED = "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"
THN_HOST = "feeds.feedburner.com"
THN_FEED = "https://feeds.feedburner.com/TheHackersNews"
VULNCHECK_HOST = "api.vulncheck.com"
VULNCHECK_INDEX = "https://api.vulncheck.com/v3/index/vulncheck-kev"
TOKEN_PATH = Path(os.environ.get("THREATSIGHT_VULNCHECK_TOKEN_FILE", "/run/secrets/vulncheck_token"))
FOCUS_CVE = "CVE-2026-58115"
VULNCHECK_MAX_PAGES = 3
VULNCHECK_RESPONSE_LIMIT = 2_000_000


def _health(db: Session, source_key: str) -> IntelligenceSourceHealth | None:
    return db.get(IntelligenceSourceHealth, source_key)


def _mark(db: Session, row: IntelligenceSourceHealth, *, ok: bool, error: str | None, digest: str | None = None, etag: str | None = None) -> None:
    row.last_attempt_at = datetime.now(UTC)
    if ok:
        row.last_success_at = row.last_attempt_at
        row.consecutive_failures = 0
        row.last_error_code = None
        if digest:
            row.last_known_good_hash = digest
        if etag is not None:
            row.etag = etag or row.etag
    else:
        row.consecutive_failures = int(row.consecutive_failures or 0) + 1
        row.last_error_code = error
    row.updated_at = datetime.now(UTC)


def _ingest(db: Session, parsed: dict, *, change_on_new: str = "source_document_added") -> dict:
    row, changed = upsert_document(db, parsed)
    cves = list((parsed.get("metadata_safe") or {}).get("cves") or [])
    if not cves:
        for assertion in parsed.get("assertions") or []:
            key = str(assertion.get("subject_key") or "")
            if key.startswith("CVE-"):
                cves.append(key)
    clusters = []
    for cve in sorted(set(cves)):
        cluster = link_cluster(db, cve=cve, document=row, title=parsed.get("title"))
        if changed:
            record_material_change(
                db,
                cluster=cluster,
                change_type=change_on_new if row.first_collected_at == row.last_collected_at else "source_document_revised",
                reason="Source document content changed or was first seen.",
                source_key=parsed["source_key"],
                old_evidence={"content_hash": None},
                new_evidence={"content_hash": row.content_hash, "external_id": row.external_id},
            )
        clusters.append(str(cluster.id))
    return {"document_id": str(row.id), "changed": changed, "clusters": clusters}


def collect_siemens(db: Session, *, focus_ssa: str | None = "SSA-834709", max_advisories: int = 5) -> dict:
    row = _health(db, "siemens-productcert")
    if row is None or not row.enabled or row.kill_switch:
        return {"state": "disabled", "source": "siemens-productcert"}
    try:
        status, meta, payload = fetch_https(SIEMENS_FEED, hostname=SIEMENS_HOST, limit=5_000_000, etag=row.etag, accept="application/json")
        if status == 304:
            _mark(db, row, ok=True, error=None)
            return {"state": "not_modified", "source": "siemens-productcert"}
        ids = parse_feed_entries(payload, limit=200)
        if focus_ssa and focus_ssa.upper() not in ids:
            ids = [focus_ssa.upper(), *ids]
        selected = []
        if focus_ssa:
            selected.append(focus_ssa.upper())
        for sid in ids:
            if sid not in selected:
                selected.append(sid)
            if len(selected) >= max_advisories:
                break
        results = []
        for sid in selected:
            url = f"https://cert-portal.siemens.com/productcert/csaf/{sid.lower()}.json"
            _, _, body = fetch_https(url, hostname=SIEMENS_HOST, limit=2_000_000, accept="application/json")
            parsed = parse_csaf(body)
            results.append(_ingest(db, parsed))
        _mark(db, row, ok=True, error=None, digest=sha256(payload), etag=meta.get("etag") or None)
        return {"state": "ok", "source": "siemens-productcert", "items": results}
    except FetchError as exc:
        _mark(db, row, ok=False, error=exc.code)
        return {"state": "failed", "source": "siemens-productcert", "error": exc.code}
    except Exception:
        _mark(db, row, ok=False, error="parse_failed")
        return {"state": "failed", "source": "siemens-productcert", "error": "parse_failed"}


def collect_thn(db: Session) -> dict:
    row = _health(db, "the-hacker-news")
    if row is None or not row.enabled or row.kill_switch:
        return {"state": "disabled", "source": "the-hacker-news"}
    try:
        status, meta, payload = fetch_https(THN_FEED, hostname=THN_HOST, limit=2_000_000, etag=row.etag, accept="application/rss+xml, application/xml, text/xml")
        if status == 304:
            _mark(db, row, ok=True, error=None)
            return {"state": "not_modified", "source": "the-hacker-news"}
        items = parse_thn_rss(payload)
        results = [_ingest(db, item) for item in items]
        _mark(db, row, ok=True, error=None, digest=sha256(payload), etag=meta.get("etag") or None)
        return {"state": "ok", "source": "the-hacker-news", "count": len(results)}
    except FetchError as exc:
        _mark(db, row, ok=False, error=exc.code)
        return {"state": "failed", "source": "the-hacker-news", "error": exc.code}
    except Exception:
        _mark(db, row, ok=False, error="parse_failed")
        return {"state": "failed", "source": "the-hacker-news", "error": "parse_failed"}


def _vulncheck_get(url: str, token: str) -> bytes:
    """Bearer GET to api.vulncheck.com only. Never logs the Authorization header."""
    import urllib.error
    import urllib.parse
    from urllib.request import Request, urlopen

    from threatsight_api.intel.http import _public_host

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != VULNCHECK_HOST:
        raise FetchError("host_rejected")
    _public_host(VULNCHECK_HOST)
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "ThreatSight-Intel/1.0",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=30) as resp:  # noqa: S310 — host validated
            if resp.status != 200:
                raise FetchError("http_status")
            payload = resp.read(VULNCHECK_RESPONSE_LIMIT + 1)
            if len(payload) > VULNCHECK_RESPONSE_LIMIT:
                raise FetchError("response_too_large")
            return payload
    except FetchError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise FetchError("unauthorized") from exc
        if exc.code == 402:
            raise FetchError("subscription_required") from exc
        if exc.code == 403:
            raise FetchError("forbidden") from exc
        if exc.code == 429:
            raise FetchError("rate_limited") from exc
        raise FetchError("http_status") from exc
    except Exception as exc:
        raise FetchError("request_failed") from exc


def collect_vulncheck(db: Session, *, focus_cve: str = FOCUS_CVE) -> dict:
    """Collect VulnCheck Community KEV via the official v3 index (not backup zip download)."""
    row = _health(db, "vulncheck-kev")
    if row is None or row.kill_switch:
        return {"state": "disabled", "source": "vulncheck-kev"}
    if not TOKEN_PATH.is_file() or TOKEN_PATH.is_symlink():
        row.enabled = False
        row.maturity = "credential_required"
        row.last_error_code = "token_missing"
        row.updated_at = datetime.now(UTC)
        return {"state": "credential_required", "source": "vulncheck-kev"}
    # Operator-installed token file is the activation signal; do not require a separate flag.
    row.enabled = True
    row.maturity = "live_collectable"
    try:
        token = TOKEN_PATH.read_text(encoding="utf-8").strip()
        if not token:
            raise FetchError("token_missing")
        # Prefer a CVE-scoped index query (bounded). Fall back to first pages if empty.
        from urllib.parse import quote

        scoped = f"{VULNCHECK_INDEX}?cve={quote(focus_cve)}&limit=100"
        payloads = [_vulncheck_get(scoped, token)]
        items = parse_vulncheck_items(payloads[0])
        if not items:
            for page in range(1, VULNCHECK_MAX_PAGES + 1):
                page_url = f"{VULNCHECK_INDEX}?page={page}&limit=100"
                body = _vulncheck_get(page_url, token)
                payloads.append(body)
                page_items = parse_vulncheck_items(body)
                items.extend(page_items)
                meta = parse_index_meta(body)
                total_pages = meta.get("total_pages")
                if total_pages is not None and page >= int(total_pages):
                    break
                if not page_items:
                    break
        focus = [item for item in items if focus_cve in (item.get("metadata_safe") or {}).get("cves", [])]
        selected = focus or items[:20]
        results = [_ingest(db, item) for item in selected]
        digest = sha256(b"".join(payloads))
        _mark(db, row, ok=True, error=None, digest=digest)
        return {
            "state": "ok",
            "source": "vulncheck-kev",
            "count": len(results),
            "focus_present": bool(focus),
            "pages": len(payloads),
        }
    except FetchError as exc:
        _mark(db, row, ok=False, error=exc.code)
        if exc.code == "token_missing":
            row.enabled = False
            row.maturity = "credential_required"
        return {"state": "failed", "source": "vulncheck-kev", "error": exc.code}
    except ValueError:
        _mark(db, row, ok=False, error="schema_drift")
        return {"state": "failed", "source": "vulncheck-kev", "error": "schema_drift"}
    except Exception:
        _mark(db, row, ok=False, error="request_failed")
        return {"state": "failed", "source": "vulncheck-kev", "error": "request_failed"}


def collect_due(db: Session) -> list[dict]:
    # Advisory lock prevents overlapping collection across worker processes.
    locked = db.execute(text("SELECT pg_try_advisory_lock(hashtext('multisource-collect'))")).scalar()
    if not locked:
        return [{"state": "skipped_lock", "source": "multisource"}]
    try:
        results = []
        results.append(collect_siemens(db))
        results.append(collect_thn(db))
        results.append(collect_vulncheck(db))
        return results
    finally:
        db.execute(text("SELECT pg_advisory_unlock(hashtext('multisource-collect'))"))
