from __future__ import annotations

import json
import re
from datetime import date

from defusedxml import ElementTree

from threatsight_api.intel.http import FetchError
from threatsight_api.landscape.sanitize import cve_list, plain, safe_https

_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def parse_epss_csv(payload: bytes) -> tuple[date, list[tuple[str, float, float]]]:
    text = payload.decode("utf-8", errors="replace")
    score_date: date | None = None
    rows: list[tuple[str, float, float]] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            lowered = line.lower()
            marker = "score_date:"
            if marker in lowered:
                raw = line[lowered.index(marker) + len(marker):].split(",", 1)[0].strip()
                score_date = date.fromisoformat(raw[:10])
            continue
        if line.lower().startswith("cve,"):
            continue
        if line[0] in "=@+-":
            raise FetchError("csv_formula")
        cve, score, percentile = (part.strip() for part in line.split(",", 2))
        cve = cve.upper()
        if not _CVE.fullmatch(cve) or cve in seen:
            continue
        try:
            score_value = float(score)
            percentile_value = float(percentile)
        except ValueError:
            continue
        if not 0.0 <= score_value <= 1.0 or not 0.0 <= percentile_value <= 1.0:
            continue
        seen.add(cve)
        rows.append((cve, score_value, percentile_value))
    if score_date is None or not rows:
        raise FetchError("unexpected_schema")
    return score_date, rows


def parse_rss(payload: bytes, limit: int = 15) -> list[dict]:
    try:
        root = ElementTree.fromstring(payload)
    except Exception as exc:
        raise FetchError("malformed_xml") from exc
    items = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] != "item":
            continue
        title = ""
        link = ""
        guid = ""
        for child in list(node):
            name = child.tag.rsplit("}", 1)[-1]
            value = plain(child.text or "", 300)
            if name == "title":
                title = value
            elif name == "link":
                link = safe_https(value) or ""
            elif name == "guid":
                guid = value[:120]
        if title and link:
            items.append({"external_id": guid or link, "title": title, "url": link, "cves": cve_list([title])})
        if len(items) >= limit:
            break
    if not items:
        raise FetchError("unexpected_schema")
    return items


def parse_nvd(payload: bytes, limit: int = 5) -> list[dict]:
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise FetchError("malformed_json") from exc
    found = []
    for item in (document.get("vulnerabilities") or [])[:limit]:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        identifier = str(cve.get("id") or "")
        if not _CVE.fullmatch(identifier):
            continue
        description = ""
        for entry in cve.get("descriptions") or []:
            if isinstance(entry, dict) and entry.get("lang") == "en":
                description = plain(entry.get("value"), 500)
                break
        found.append(
            {
                "external_id": identifier,
                "title": plain(f"{identifier} {description}", 180),
                "summary": description or "NVD description was not supplied.",
                "url": f"https://nvd.nist.gov/vuln/detail/{identifier}",
                "cves": [identifier],
                "withdrawn": str(cve.get("vulnStatus") or "").lower() == "rejected",
            }
        )
    return found


def parse_epss_header_only(sample: str) -> date:
    for line in sample.splitlines():
        if line.lower().startswith("#score_date:"):
            return date.fromisoformat(line.split(":", 1)[1].strip())
    raise FetchError("unexpected_schema")
