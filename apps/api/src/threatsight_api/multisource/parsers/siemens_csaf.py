"""Parse Siemens ProductCERT CSAF 2.0 advisories into safe documents/assertions."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from threatsight_api.multisource import PARSER_VERSION

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Explicit vendor exploitation confirmation only. Do not match speculative
# "could allow" / "could exploit" wording or remediation urgency alone.
VENDOR_EXPLOITATION_RE = re.compile(
    r"("
    r"current known active exploitation"
    r"|known active exploitation"
    r"|actively exploited"
    r"|exploited in the wild"
    r"|exploitation (?:has been|was) (?:observed|confirmed|detected)"
    r"|known to be exploited"
    r")",
    re.IGNORECASE,
)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _collect_note_text(data: dict[str, Any]) -> str:
    parts: list[str] = []
    for note in (data.get("document") or {}).get("notes") or []:
        if isinstance(note, dict):
            parts.append(str(note.get("text") or ""))
    for vuln in data.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        for note in vuln.get("notes") or []:
            if isinstance(note, dict):
                parts.append(str(note.get("text") or ""))
        for threat in vuln.get("threats") or []:
            if isinstance(threat, dict):
                parts.append(str(threat.get("details") or ""))
    return "\n".join(parts)


def vendor_exploitation_confirmed_from_text(text: str) -> bool:
    """True only when official vendor wording explicitly confirms known exploitation."""
    if not text:
        return False
    # Speculative "could allow/exploit" language alone must not match.
    return bool(VENDOR_EXPLOITATION_RE.search(text))


def parse_csaf(payload: bytes) -> dict[str, Any]:
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict) or "document" not in data:
        raise ValueError("malformed_csaf")
    doc = data["document"]
    tracking = doc.get("tracking") or {}
    external_id = str(tracking.get("id") or "").strip()
    if not external_id:
        raise ValueError("missing_ssa_id")
    title = str(doc.get("title") or external_id)[:500]
    published = _parse_dt(tracking.get("initial_release_date"))
    updated = _parse_dt(tracking.get("current_release_date"))
    refs = doc.get("references") or []
    canonical = None
    for ref in refs:
        if isinstance(ref, dict) and ref.get("category") == "self" and str(ref.get("url", "")).endswith(".json"):
            canonical = str(ref["url"])[:1000]
            break
    if canonical is None:
        canonical = f"https://cert-portal.siemens.com/productcert/csaf/{external_id.lower()}.json"

    products: dict[str, dict[str, Any]] = {}
    tree = data.get("product_tree") or {}

    def walk(branch: dict[str, Any], vendor: str = "", product_name: str = "") -> None:
        category = branch.get("category")
        name = str(branch.get("name") or "")
        if category == "vendor":
            vendor = name
        elif category == "product_name":
            product_name = name
        product = branch.get("product")
        if isinstance(product, dict) and product.get("product_id"):
            helpers = product.get("product_identification_helper") or {}
            models = helpers.get("model_numbers") or []
            products[str(product["product_id"])] = {
                "name": str(product.get("name") or product_name)[:500],
                "vendor": vendor or "Siemens",
                "model_numbers": [str(m) for m in models][:20],
                "version_range": name if category == "product_version_range" else None,
            }
        for child in branch.get("branches") or []:
            if isinstance(child, dict):
                walk(child, vendor=vendor, product_name=product_name)

    for root in tree.get("branches") or []:
        if isinstance(root, dict):
            walk(root)

    note_text = _collect_note_text(data)
    exploitation_confirmed = vendor_exploitation_confirmed_from_text(note_text)

    assertions: list[dict[str, Any]] = []
    cves: list[str] = []
    for vuln in data.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        cve = str(vuln.get("cve") or "").upper()
        if not CVE_RE.fullmatch(cve):
            continue
        cves.append(cve)
        subject = cve
        assertions.append(
            {
                "subject_key": subject,
                "assertion_type": "vendor_vulnerability_confirmed",
                "value": {"ssa_id": external_id, "status": tracking.get("status")},
                "observed_at": updated or published,
                "limitations": [
                    "vendor_advisory_confirms_vulnerability_not_customer_impact",
                    "vendor_vulnerability_is_not_vendor_exploitation",
                ],
            }
        )
        if exploitation_confirmed:
            match = VENDOR_EXPLOITATION_RE.search(note_text)
            assertions.append(
                {
                    "subject_key": subject,
                    "assertion_type": "vendor_exploitation_confirmed",
                    "value": {
                        "ssa_id": external_id,
                        "evidence_phrase": (match.group(0) if match else "known active exploitation")[:200],
                        "exploitation_confirmed": True,
                    },
                    "observed_at": updated or published,
                    "limitations": [
                        "vendor_exploitation_claim_is_not_customer_targeting",
                        "requires_official_vendor_wording",
                    ],
                }
            )
        for pid in (vuln.get("product_status") or {}).get("known_affected") or []:
            meta = products.get(str(pid), {})
            assertions.append(
                {
                    "subject_key": subject,
                    "assertion_type": "product_affected",
                    "value": {
                        "product_name": meta.get("name"),
                        "model_numbers": meta.get("model_numbers") or [],
                        "vendor": meta.get("vendor") or "Siemens",
                        "product_id": str(pid),
                    },
                    "observed_at": updated or published,
                    "limitations": ["structured_product_status_only"],
                }
            )
            version_range = meta.get("version_range")
            if version_range:
                assertions.append(
                    {
                        "subject_key": subject,
                        "assertion_type": "version_affected",
                        "value": {"expression": version_range, "product_id": str(pid)},
                        "observed_at": updated or published,
                        "limitations": ["version_expression_from_csaf"],
                    }
                )
            product_label = str(meta.get("name") or "")
            if "Node-RED" in product_label or "node-red" in product_label.lower():
                assertions.append(
                    {
                        "subject_key": subject,
                        "assertion_type": "prerequisite_required",
                        "value": {"prerequisite": "node_red_installed", "product_id": str(pid)},
                        "observed_at": updated or published,
                        "limitations": ["prerequisite_from_structured_product_name"],
                    }
                )
        for rem in vuln.get("remediations") or []:
            if not isinstance(rem, dict):
                continue
            category = rem.get("category")
            details = str(rem.get("details") or "")[:500]
            if category == "vendor_fix":
                assertions.append(
                    {
                        "subject_key": subject,
                        "assertion_type": "fixed_version",
                        "value": {"details": details, "url": rem.get("url")},
                        "observed_at": updated or published,
                        "limitations": ["remediation_from_csaf"],
                    }
                )
                assertions.append(
                    {
                        "subject_key": subject,
                        "assertion_type": "remediation_available",
                        "value": {"details": details, "url": rem.get("url")},
                        "observed_at": updated or published,
                        "limitations": ["remediation_from_csaf"],
                    }
                )
            elif category == "mitigation":
                assertions.append(
                    {
                        "subject_key": subject,
                        "assertion_type": "mitigation_available",
                        "value": {"details": details},
                        "observed_at": updated or published,
                        "limitations": ["mitigation_from_csaf"],
                    }
                )

    return {
        "source_key": "siemens-productcert",
        "source_role": "vendor_authority",
        "external_id": external_id,
        "canonical_url": canonical,
        "title": title,
        "published_at": published,
        "source_updated_at": updated,
        "metadata_safe": {
            "ssa_id": external_id,
            "cves": sorted(set(cves)),
            "vendor_status": tracking.get("status"),
            "version": tracking.get("version"),
            "attribution": "Siemens ProductCERT CSAF",
            "vendor_exploitation_confirmed": exploitation_confirmed,
        },
        "parser_version": PARSER_VERSION,
        "assertions": assertions,
    }


def parse_feed_entries(payload: bytes, *, limit: int = 50) -> list[str]:
    data = json.loads(payload.decode("utf-8"))
    entries = ((data.get("feed") or {}).get("entry")) or []
    ids: list[str] = []
    for entry in entries[:limit]:
        if not isinstance(entry, dict):
            continue
        sid = str(entry.get("id") or "").strip()
        if sid.upper().startswith("SSA-"):
            ids.append(sid.upper())
    return ids
