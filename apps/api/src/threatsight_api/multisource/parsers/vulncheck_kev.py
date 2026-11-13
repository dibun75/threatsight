"""Parse VulnCheck Community KEV index records into exploitation observations.

Official schema (docs.vulncheck.com/community/vulncheck-kev/schema, reviewed 2026-11-03):
- ``cve`` is an array of CVE strings
- ``vulncheck_reported_exploitation`` is a list of citation objects (url, date_added)
- ``reported_exploited_by_vulncheck_canaries`` is a boolean for canary observation
- ``vulncheck_xdb`` references public exploit/PoC indexes (metadata only; never fetched)
- ``cisa_date_added`` is informational and must not set government_catalogued
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from threatsight_api.multisource import PARSER_VERSION

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
MAX_ITEMS = 200
MAX_CITATIONS = 20
MAX_XDB = 10


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _safe_https_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    # Never retain git clone URLs or non-https exploit payload hosts for fetching.
    if parsed.hostname.endswith("github.com") and parsed.path.endswith(".git"):
        return None
    return value.strip()[:1000]


def _cves_from_row(row: dict[str, Any]) -> list[str]:
    raw = row.get("cve") or row.get("CVE") or []
    values: list[str] = []
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, list):
        values = [str(item) for item in raw]
    out: list[str] = []
    for item in values:
        cve = item.strip().upper()
        if CVE_RE.fullmatch(cve):
            out.append(cve)
    return sorted(set(out))


def parse_vulncheck_items(payload: bytes, *, limit: int = MAX_ITEMS) -> list[dict[str, Any]]:
    data = json.loads(payload.decode("utf-8"))
    if isinstance(data, dict) and data.get("error") is True:
        raise ValueError("vulncheck_api_error")
    rows = data if isinstance(data, list) else data.get("data") or []
    if not isinstance(rows, list):
        raise ValueError("malformed_vulncheck")
    out: list[dict[str, Any]] = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        cves = _cves_from_row(row)
        if not cves:
            continue
        date_added = _parse_dt(row.get("date_added"))
        updated = _parse_dt(row.get("_timestamp")) or date_added
        canary = bool(row.get("reported_exploited_by_vulncheck_canaries"))
        citations_raw = row.get("vulncheck_reported_exploitation") or []
        citations: list[dict[str, str]] = []
        if isinstance(citations_raw, list):
            for item in citations_raw[:MAX_CITATIONS]:
                if not isinstance(item, dict):
                    continue
                url = _safe_https_url(item.get("url"))
                if url is None:
                    continue
                citations.append(
                    {
                        "url": url,
                        "date_added": str(item.get("date_added") or "")[:64],
                    }
                )
        xdb_raw = row.get("vulncheck_xdb") or []
        xdb_ids: list[str] = []
        if isinstance(xdb_raw, list):
            for item in xdb_raw[:MAX_XDB]:
                if isinstance(item, dict) and item.get("xdb_id"):
                    xdb_ids.append(str(item["xdb_id"])[:64])
        vendor = str(row.get("vendorProject") or "")[:200]
        product = str(row.get("product") or "")[:200]
        name = str(row.get("vulnerabilityName") or "")[:500]
        for cve in cves:
            external_id = f"vulncheck-kev:{cve}"
            title = (name or f"VulnCheck KEV entry for {cve}")[:500]
            assertions: list[dict[str, Any]] = [
                {
                    "subject_key": cve,
                    "assertion_type": "researcher_catalogued",
                    "value": {
                        "catalog": "vulncheck_kev",
                        "attribution": "VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV)",
                        "vendor_project": vendor or None,
                        "product": product or None,
                        "citation_count": len(citations),
                        "not_cisa_kev": True,
                        "not_direct_observation": True,
                    },
                    "observed_at": date_added,
                    "limitations": [
                        "vulncheck_kev_is_not_cisa_kev",
                        "vulncheck_kev_is_not_direct_canary_observation",
                        "researcher_catalog_is_not_vendor_truth",
                        "observation_elsewhere_is_not_customer_targeting",
                        "requires_vulncheck_attribution",
                    ],
                }
            ]
            if canary:
                assertions.append(
                    {
                        "subject_key": cve,
                        "assertion_type": "researcher_exploitation_observed",
                        "value": {
                            "attribution": "VulnCheck canaries",
                            "method": "reported_exploited_by_vulncheck_canaries",
                        },
                        "observed_at": updated or date_added,
                        "limitations": [
                            "canary_observation_is_not_customer_targeting",
                            "researcher_observation_is_not_vendor_exploitation_confirmation",
                            "requires_vulncheck_attribution",
                        ],
                    }
                )
            # Do not assert government_catalogued from cisa_date_added — CISA KEV stays separate.
            out.append(
                {
                    "source_key": "vulncheck-kev",
                    "source_role": "exploitation_observation",
                    "external_id": external_id[:256],
                    "canonical_url": "https://docs.vulncheck.com/community/vulncheck-kev",
                    "title": title,
                    "published_at": date_added,
                    "source_updated_at": updated,
                    "metadata_safe": {
                        "cves": [cve],
                        "attribution": "VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV)",
                        "vendor_project": vendor or None,
                        "product": product or None,
                        "known_ransomware_campaign_use": row.get("knownRansomwareCampaignUse"),
                        "reported_exploited_by_vulncheck_canaries": canary,
                        "citation_count": len(citations),
                        "citations": citations[:5],
                        "xdb_id_count": len(xdb_ids),
                        "xdb_ids": xdb_ids,
                        "cisa_date_added_present": bool(row.get("cisa_date_added")),
                        "note": "cisa_date_added on a VulnCheck record is not a live CISA KEV assertion",
                    },
                    "parser_version": PARSER_VERSION,
                    "assertions": assertions,
                }
            )
    return out


def parse_index_meta(payload: bytes) -> dict[str, Any]:
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict):
        return {}
    meta = data.get("_meta") or data.get("meta") or {}
    if not isinstance(meta, dict):
        return {}
    return {
        "page": meta.get("page") or meta.get("current_page"),
        "total_pages": meta.get("total_pages") or meta.get("last_page"),
        "total_documents": meta.get("total_documents") or meta.get("total"),
    }
