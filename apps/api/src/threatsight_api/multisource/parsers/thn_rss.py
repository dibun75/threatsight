"""Parse The Hacker News RSS into media-discovery metadata only."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse, urlunparse

from threatsight_api.multisource import PARSER_VERSION

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
MAX_ITEMS = 40
MAX_EXCERPT = 500
# Reject DTD / entity expansion by using defused-style limits via ET defaults + size cap.


def _strip_html(text: str) -> str:
    cleaned = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", cleaned).strip()


def _canonical(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme != "https" or parsed.hostname not in {"thehackernews.com", "www.thehackernews.com"}:
        raise ValueError("host_rejected")
    clean = parsed._replace(query="", fragment="")
    return urlunparse(clean)[:1000]


def parse_thn_rss(payload: bytes) -> list[dict[str, Any]]:
    if b"<!DOCTYPE" in payload[:200].upper() or b"<!ENTITY" in payload.upper():
        raise ValueError("xml_entities_rejected")
    root = ET.fromstring(payload)
    channel = root.find("channel")
    if channel is None:
        raise ValueError("malformed_rss")
    out: list[dict[str, Any]] = []
    for item in channel.findall("item")[:MAX_ITEMS]:
        title = (item.findtext("title") or "").strip()[:500]
        link = (item.findtext("link") or item.findtext("guid") or "").strip()
        if not title or not link:
            continue
        try:
            canonical = _canonical(link)
        except ValueError:
            continue
        description = _strip_html(item.findtext("description") or "")[:MAX_EXCERPT]
        pub = item.findtext("pubDate")
        published = None
        if pub:
            try:
                published = parsedate_to_datetime(pub)
            except (TypeError, ValueError, IndexError):
                published = None
        author = (item.findtext("{http://purl.org/dc/elements/1.1/}creator") or item.findtext("author") or "").strip()[:200]
        haystack = f"{title}\n{description}"
        cves = sorted({m.group(0).upper() for m in CVE_RE.finditer(haystack)})
        assertions: list[dict[str, Any]] = []
        for cve in cves:
            assertions.append(
                {
                    "subject_key": cve,
                    "assertion_type": "media_exploitation_reported",
                    "value": {"media": True, "confidence_role": "media_discovery"},
                    "observed_at": published,
                    "limitations": [
                        "media_discovery_is_not_vendor_truth",
                        "media_is_not_vendor_exploitation_confirmation",
                        "headline_is_not_proof_of_exploitation",
                    ],
                }
            )
        out.append(
            {
                "source_key": "the-hacker-news",
                "source_role": "media_discovery",
                "external_id": canonical,
                "canonical_url": canonical,
                "title": title,
                "published_at": published,
                "source_updated_at": published,
                "metadata_safe": {
                    "author": author or None,
                    "excerpt": description,
                    "cves": cves,
                    "attribution": "The Hacker News",
                },
                "parser_version": PARSER_VERSION,
                "assertions": assertions,
            }
        )
    return out
