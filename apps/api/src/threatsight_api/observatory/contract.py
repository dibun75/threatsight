"""Strict parsers for bounded SANS ISC / DShield static feeds."""

from __future__ import annotations

from datetime import date
import ipaddress
import re

MAX_ROWS = 250
_SAFE = re.compile(r"^[\w .:/,+()#@'-]{0,300}$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
# Placeholder codes the source uses for "unknown" or non-country locations.
_UNKNOWN_COUNTRY = {"XX", "ZZ", "A1", "A2", "AP", "EU", "O1"}


class ObservatoryError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _text(payload: bytes) -> str:
    try:
        value = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ObservatoryError("encoding") from exc
    if "\x00" in value:
        raise ObservatoryError("encoding")
    return value


def _public_ipv4(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4 or not address.is_global:
        return None
    return str(address)


def _safe(value: object, *, maximum: int = 300) -> str:
    text = str(value or "").strip()[:maximum]
    if not _SAFE.fullmatch(text):
        raise ObservatoryError("unsafe_text")
    return text


def _date(value: str) -> str | None:
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        return None


def parse_top_ips(payload: bytes) -> list[dict]:
    rows: list[dict] = []
    for line in _text(payload).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        address = _public_ipv4(fields[0].strip())
        if not address:
            continue
        try:
            hostname = _safe(fields[1] if len(fields) > 1 else "", maximum=253)
        except ObservatoryError:
            continue
        rows.append({
            "kind": "scanning_source",
            "indicator_type": "ipv4",
            "indicator": address,
            "category": "high_volume_source",
            "detail": hostname,
            "rank": len(rows) + 1,
            "reference_url": "https://feeds.dshield.org/feeds/topips.txt",
        })
        if len(rows) >= 100:
            break
    return rows


def parse_top_ports(payload: bytes) -> list[dict]:
    rows: list[dict] = []
    for line in _text(payload).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        try:
            port = int(fields[0])
        except (ValueError, IndexError):
            continue
        if not 1 <= port <= 65535:
            continue
        try:
            service = _safe(fields[1] if len(fields) > 1 else "", maximum=80)
            detail = _safe(fields[2] if len(fields) > 2 else "", maximum=300)
        except ObservatoryError:
            continue
        rows.append({
            "kind": "target_port",
            "indicator_type": "port",
            "indicator": str(port),
            "port": port,
            "service": service,
            "category": "observed_target_port",
            "detail": detail,
            "rank": len(rows) + 1,
            "reference_url": "https://feeds.dshield.org/feeds/topports.txt",
        })
        if len(rows) >= 50:
            break
    return rows


def _category(label: str) -> str | None:
    lowered = label.lower()
    for needle, category in (
        ("blocklistdebruteforce", "brute_force_report"),
        ("blocklistde", "blocklist_observation"),
        ("ciarmy", "blocklist_observation"),
        ("censys", "internet_measurement"),
        ("internetcensus", "internet_measurement"),
        ("internetmeasurement", "internet_measurement"),
        ("rapid7sonar", "internet_measurement"),
        ("stretchoid", "internet_measurement"),
        ("onyphe", "internet_measurement"),
        ("torexit", "anonymity_infrastructure"),
        ("shadowserver", "security_research_observation"),
        ("dshieldssh", "ssh_scanning"),
        ("dshieldweb", "web_scanning"),
        ("dshield", "multi_port_scanning"),
        ("miner", "cryptomining_infrastructure"),
        ("botnet", "botnet_infrastructure"),
        ("brute", "brute_force"),
        ("telnet", "telnet_scanning"),
        ("scanner", "scanning_source"),
        ("webscan", "web_scanning"),
    ):
        if needle in lowered:
            return category
    return None


def parse_threat_intel(payload: bytes) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    country_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for line in _text(payload).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("date\t"):
            continue
        fields = line.split("\t")
        if len(fields) < 5:
            continue
        first_seen, last_seen, raw_ip, raw_label, raw_country = fields[:5]
        address = _public_ipv4(raw_ip.strip())
        category = _category(raw_label)
        if not address or not category or address in seen:
            continue
        try:
            label = _safe(raw_label, maximum=80)
        except ObservatoryError:
            continue
        country = raw_country.strip().upper()
        if not _COUNTRY.fullmatch(country) or country in _UNKNOWN_COUNTRY:
            country = None
        country_bucket = country or "unknown"
        if country_counts.get(country_bucket, 0) >= 5 or category_counts.get(category, 0) >= 80:
            continue
        country_counts[country_bucket] = country_counts.get(country_bucket, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
        seen.add(address)
        rows.append({
            "kind": "reported_infrastructure",
            "indicator_type": "ipv4",
            "indicator": address,
            "category": category,
            "country_code": country,
            "first_seen": _date(first_seen),
            "last_seen": _date(last_seen),
            "detail": label,
            "rank": len(rows) + 1,
            "reference_url": "https://isc.sans.edu/feeds/threatintel.txt",
        })
        if len(rows) >= MAX_ROWS:
            break
    return rows
