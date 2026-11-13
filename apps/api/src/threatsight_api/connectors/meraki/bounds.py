"""Bounds for the read-only Meraki Dashboard connector."""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from urllib.parse import parse_qsl, urlsplit

from threatsight_api.connectors.microsoft.bounds import (
    MAX_RESPONSE_BYTES,
    CollectionFailure,
    credential_refused,
    safe_label,
)

ORIGIN = "https://api.meraki.com"
API_PREFIX = "/api/v1"
MAX_VENDOR_PAGES = 3
MAX_HTTP_CALLS = 30
MAX_COLLECTION_SECONDS = 60
PAGE_SIZE = 100
ORG_ID = re.compile(r"^[0-9]{1,20}$")
NETWORK_ID = re.compile(r"^L_[0-9]{8,20}$")
SERIAL = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")
TOKEN = re.compile(r"^[A-Za-z0-9._~-]{1,200}$")
PRODUCTS = frozenset({
    "appliance", "switch", "wireless", "camera", "cellularGateway", "sensor",
    "secureConnect", "systemsManager", "wirelessController", "campusGateway",
})
INTERFACES = frozenset({"wan1", "wan2", "wan3", "cellular", "man1"})
UPLINK_STATUS = frozenset({"active", "connecting", "failed", "not connected", "ready"})
HA_ROLES = frozenset({"primary", "spare"})
QUERY_KEYS = frozenset({"perPage", "startingAfter", "endingBefore"})


def clean_identifier(value: object, pattern: re.Pattern[str]) -> str | None:
    text = str(value or "")
    if pattern.fullmatch(text) is None:
        return None
    return text


def public_label(value: object, limit: int = 80) -> str:
    text = safe_label(value, limit)
    lowered = text.lower()
    if not text or "@" in text or "://" in text or "bearer" in lowered or "api_key" in lowered:
        return ""
    return text


def clean_ip(value: object) -> str | None:
    try:
        parsed = ip_address(str(value or "").strip())
    except ValueError:
        return None
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local:
        return None
    return str(parsed)


def clean_subnet(value: object) -> str | None:
    try:
        parsed = ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None
    if parsed.prefixlen == 0 or parsed.is_multicast:
        return None
    return str(parsed)


def approved_url(url: str, *, origin: str = ORIGIN, path: str | None = None) -> str:
    parsed = urlsplit(url)
    expected = urlsplit(origin)
    if (
        parsed.scheme != expected.scheme
        or parsed.hostname != expected.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port != expected.port
    ):
        raise CollectionFailure("destination_refused")
    if expected.scheme == "https" and parsed.port not in {None, 443}:
        raise CollectionFailure("destination_refused")
    if not parsed.path.startswith(f"{API_PREFIX}/") and parsed.path != API_PREFIX:
        raise CollectionFailure("destination_refused")
    if path is not None and parsed.path != path:
        raise CollectionFailure("destination_refused")
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key not in QUERY_KEYS or "://" in value or TOKEN.fullmatch(value) is None:
            raise CollectionFailure("destination_refused")
        if key == "perPage" and value != str(PAGE_SIZE):
            raise CollectionFailure("destination_refused")
    return url


__all__ = [
    "MAX_COLLECTION_SECONDS",
    "MAX_HTTP_CALLS",
    "MAX_RESPONSE_BYTES",
    "MAX_VENDOR_PAGES",
    "ORIGIN",
    "PAGE_SIZE",
    "CollectionFailure",
    "approved_url",
    "clean_identifier",
    "clean_ip",
    "clean_subnet",
    "credential_refused",
    "public_label",
]
