from __future__ import annotations

import hashlib
import html
import json
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as XmlSerialization

from defusedxml import ElementTree
from threatsight_api.radar.contracts import NormalizedThreatEvent

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TAG_PATTERN = re.compile(r"<[^>]+>")
PARSER_VERSION = "phase1-v1"


def _payload_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _plain_text(value: object) -> str:
    text = html.unescape(str(value or ""))
    return re.sub(r"\s+", " ", TAG_PATTERN.sub(" ", text)).strip()[:2_000]


def _xml_root(payload: bytes):
    try:
        return ElementTree.fromstring(payload)
    except Exception as exc:
        raise ValueError("Threat-source XML is invalid or unsafe") from exc


def _child_text(element, local_name: str) -> str:
    for child in element.iter():
        if child.tag.rsplit("}", 1)[-1] == local_name:
            return (child.text or "").strip()
    return ""


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    result: datetime | None = None
    for parser in (
        lambda current: datetime.fromisoformat(current.replace("Z", "+00:00")),
        parsedate_to_datetime,
        lambda current: datetime.strptime(current, "%b %d, %Y, %I:%M:%S %p"),
    ):
        try:
            result = parser(text)
            break
        except (TypeError, ValueError):
            continue
    if result is None:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=UTC)
    return result


def parse_cisa_kev(payload: bytes) -> list[NormalizedThreatEvent]:
    document = json.loads(payload)
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise ValueError("Invalid CISA KEV document")
    events: list[NormalizedThreatEvent] = []
    for item in document["vulnerabilities"]:
        cve = str(item.get("cveID", "")).upper()
        vendor = str(item.get("vendorProject", "")).strip()
        product = str(item.get("product", "")).strip()
        events.append(
            NormalizedThreatEvent(
                external_id=cve,
                event_type="vulnerability",
                title=f"{cve} — {vendor} {product}".strip(),
                summary=str(item.get("shortDescription", "")).strip() or "Known exploited vulnerability",
                canonical_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve}",
                published_at=_date(item.get("dateAdded")),
                source_updated_at=_date(document.get("dateReleased")),
                countries=["US"],
                authority_jurisdictions=["US"],
                vendors=[vendor] if vendor else [],
                products=[product] if product else [],
                cves=[cve],
                exploitation_status="known_exploited",
                source_payload_hash=_payload_hash(
                    json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
                ),
                parser_version=PARSER_VERSION,
                provenance={"authority": "CISA", "catalog": "KEV"},
                limitations=["Authority jurisdiction does not identify target, victim, infrastructure, or attacker origin."],
                attributes={
                    "required_action": item.get("requiredAction"),
                    "due_date": item.get("dueDate"),
                    "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
                    "catalog_version": document.get("catalogVersion"),
                },
            )
        )
    return events


def parse_nsm_rss(payload: bytes) -> list[NormalizedThreatEvent]:
    root = _xml_root(payload)
    events: list[NormalizedThreatEvent] = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        guid = (item.findtext("guid") or link or title).strip()
        raw_description = item.findtext("description") or ""
        summary = _plain_text(raw_description) or title
        cves = sorted({match.upper() for match in CVE_PATTERN.findall(f"{title} {summary}")})
        if not title or not link:
            continue
        events.append(
            NormalizedThreatEvent(
                external_id=guid[:200],
                event_type="advisory",
                title=title,
                summary=summary,
                canonical_url=link,
                published_at=_date(item.findtext("pubDate")),
                countries=["NO"],
                authority_jurisdictions=["NO"],
                cves=cves,
                source_payload_hash=_payload_hash(XmlSerialization.tostring(item)),
                parser_version=PARSER_VERSION,
                provenance={"authority": "NSM", "feed_format": "rss"},
                limitations=["Authority jurisdiction is not evidence of target, victim, infrastructure, or attacker origin."],
                attributes={"language": "nb", "authority": "NSM"},
            )
        )
    return events


def parse_first_epss(payload: bytes) -> dict[str, tuple[float, float, datetime | None]]:
    document = json.loads(payload)
    if not isinstance(document, dict) or not isinstance(document.get("data"), list):
        raise ValueError("Invalid FIRST EPSS document")
    result: dict[str, tuple[float, float, datetime | None]] = {}
    for item in document["data"]:
        cve = str(item.get("cve", "")).upper()
        if not CVE_PATTERN.fullmatch(cve):
            continue
        result[cve] = (
            float(item["epss"]),
            float(item["percentile"]),
            _date(item.get("date")),
        )
    return result


def parse_authority_rss(
    payload: bytes,
    *,
    authority: str,
    jurisdiction: str,
    language: str,
) -> list[NormalizedThreatEvent]:
    root = _xml_root(payload)
    events: list[NormalizedThreatEvent] = []
    for item in root.findall(".//item"):
        title = _plain_text(item.findtext("title"))
        link = (item.findtext("link") or "").strip()
        external_id = (item.findtext("guid") or link or title).strip()
        summary = _plain_text(item.findtext("description")) or title
        if not title or not link or not external_id:
            continue
        cves = sorted({match.upper() for match in CVE_PATTERN.findall(f"{title} {summary}")})
        exploitation = (
            "proof_of_concept"
            if re.search(r"\b(PoC|proof[- ]of[- ]concept)\b", summary, re.IGNORECASE)
            else "unknown"
        )
        events.append(
            NormalizedThreatEvent(
                external_id=external_id[:200],
                event_type="advisory",
                title=title,
                summary=summary,
                canonical_url=link,
                published_at=_date(item.findtext("pubDate")),
                countries=[jurisdiction],
                authority_jurisdictions=[jurisdiction],
                cves=cves,
                exploitation_status=exploitation,
                source_payload_hash=_payload_hash(XmlSerialization.tostring(item)),
                parser_version=PARSER_VERSION,
                provenance={"authority": authority, "feed_format": "rss", "language": language},
                limitations=[
                    "Authority jurisdiction is not evidence of target, victim, infrastructure, or attacker origin.",
                    "Feed text is stored only as a bounded plain-text excerpt with a canonical source link.",
                ],
                attributes={"language": language, "authority": authority},
            )
        )
    return events


def parse_cert_se_atom(payload: bytes) -> list[NormalizedThreatEvent]:
    root = _xml_root(payload)
    events: list[NormalizedThreatEvent] = []
    for entry in [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "entry"]:
        title = _plain_text(_child_text(entry, "title"))
        summary = _plain_text(_child_text(entry, "summary") or _child_text(entry, "content")) or title
        external_id = _child_text(entry, "id")
        link = ""
        for child in entry.iter():
            if child.tag.rsplit("}", 1)[-1] == "link" and child.attrib.get("href"):
                link = child.attrib["href"].strip()
                if child.attrib.get("rel", "alternate") == "alternate":
                    break
        if not title or not link:
            continue
        events.append(
            NormalizedThreatEvent(
                external_id=(external_id or link)[:200],
                event_type="advisory",
                title=title,
                summary=summary,
                canonical_url=link,
                published_at=_date(_child_text(entry, "published")),
                source_updated_at=_date(_child_text(entry, "updated")),
                countries=["SE"],
                authority_jurisdictions=["SE"],
                cves=sorted({match.upper() for match in CVE_PATTERN.findall(f"{title} {summary}")}),
                source_payload_hash=_payload_hash(XmlSerialization.tostring(entry)),
                parser_version=PARSER_VERSION,
                provenance={"authority": "CERT-SE", "feed_format": "atom", "language": "sv"},
                limitations=[
                    "Authority jurisdiction is not evidence of target, victim, infrastructure, or attacker origin.",
                    "Feed text is stored only as a bounded plain-text excerpt with a canonical source link.",
                ],
                attributes={"language": "sv", "authority": "CERT-SE"},
            )
        )
    return events


def parse_enisa_euvd(payload: bytes) -> list[NormalizedThreatEvent]:
    document = json.loads(payload)
    if not isinstance(document, dict) or not isinstance(document.get("items"), list):
        raise ValueError("Invalid ENISA EUVD document")
    events: list[NormalizedThreatEvent] = []
    for item in document["items"]:
        if not isinstance(item, dict):
            continue
        external_id = str(item.get("id", "")).strip()
        summary = _plain_text(item.get("description"))
        if not external_id or not summary:
            continue
        cves = sorted({match.upper() for match in CVE_PATTERN.findall(str(item.get("aliases", "")))})
        vendor_values = [
            str(value.get("name", "")).strip()
            for value in item.get("enisaIdVendor", [])
            if isinstance(value, dict) and value.get("name")
        ]
        product_values = [
            str(value.get("name", "")).strip()
            for value in item.get("enisaIdProduct", [])
            if isinstance(value, dict) and value.get("name")
        ]
        events.append(
            NormalizedThreatEvent(
                external_id=external_id[:200],
                event_type="vulnerability",
                title=f"{external_id} — {summary[:160]}",
                summary=summary,
                canonical_url=f"https://euvd.enisa.europa.eu/vulnerability/{external_id}",
                published_at=_date(item.get("datePublished")),
                source_updated_at=_date(item.get("dateUpdated")),
                countries=["EU"],
                authority_jurisdictions=["EU"],
                vendors=vendor_values,
                products=product_values,
                cves=cves,
                source_payload_hash=_payload_hash(
                    json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
                ),
                parser_version=PARSER_VERSION,
                provenance={"authority": "ENISA", "dataset": "EUVD", "enisa_uuid": item.get("enisaUuid")},
                limitations=[
                    "Authority jurisdiction is not evidence of target, victim, infrastructure, or attacker origin.",
                    "Referenced vulnerability data may retain third-party rights; only metadata and source links are stored.",
                ],
                attributes={
                    "base_score": item.get("baseScore"),
                    "epss": item.get("epss"),
                    "assigner": item.get("assigner"),
                },
            )
        )
    return events
