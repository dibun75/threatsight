"""Bounded abuse.ch Feodo Tracker and URLhaus recent-feed clients.

Both feeds are published by abuse.ch under CC0. They are optional: an Auth-Key
(free, https://auth.abuse.ch/) is sent when a key file is configured, because
abuse.ch has been moving its feeds behind that key.
"""
from __future__ import annotations

from datetime import datetime
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from threatsight_api.observatory.contract import ObservatoryError
from threatsight_api.observatory.threatfox import _DOMAIN, _safe, read_auth_key

FEEDS = {
    "feodo": ("feodotracker.abuse.ch", "/downloads/ipblocklist.json"),
    # The json_recent download returns 410 Gone since Nov 2026; the API endpoint needs the Auth-Key.
    "urlhaus": ("urlhaus-api.abuse.ch", "/v1/urls/recent/limit/1000/"),
}
MAX_RESPONSE = 6_000_000
MAX_ROWS = 250
_COUNTRY = re.compile(r"^[A-Z]{2}$")


def fetch_feed(feed: str, token_file: str = "", *, opener=None) -> bytes:
    if feed not in FEEDS:
        raise ObservatoryError("request_rejected")
    host, path = FEEDS[feed]
    headers = {"Accept": "application/json", "User-Agent": "ThreatSight/1.0 (+https://threatsight.io)"}
    if token_file:
        headers["Auth-Key"] = read_auth_key(token_file)
    request = urllib.request.Request(f"https://{host}{path}", headers=headers, method="GET")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ObservatoryError("redirect_rejected")

    active = opener or urllib.request.build_opener(_NoRedirect)
    try:
        response = active.open(request, timeout=30)
    except ObservatoryError:
        raise
    except urllib.error.HTTPError as exc:
        code = "unauthorized" if exc.code in {401, 403} else "rate_limited" if exc.code == 429 else "http_status"
        raise ObservatoryError(code) from exc
    except Exception as exc:
        raise ObservatoryError("request_failed") from exc
    final = urllib.parse.urlparse(response.geturl())
    if final.scheme != "https" or final.hostname != host or final.path != path:
        raise ObservatoryError("redirect_rejected")
    payload = response.read(MAX_RESPONSE + 1)
    if len(payload) > MAX_RESPONSE:
        raise ObservatoryError("response_too_large")
    return payload


def _load(payload: bytes):
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObservatoryError("schema_drift") from exc


def _day(value: object) -> str | None:
    text = str(value or "").replace(" UTC", "").strip()
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:19] if " " in text else text[:10], pattern).date().isoformat()
        except ValueError:
            continue
    return None


def parse_feodo(payload: bytes) -> list[dict]:
    """Botnet C2 servers. The source supplies the hosting country, so rows can be placed on the map."""
    document = _load(payload)
    if not isinstance(document, list):
        raise ObservatoryError("schema_drift")
    rows: list[dict] = []
    seen: set[str] = set()
    for item in document:
        if not isinstance(item, dict):
            continue
        try:
            address = ipaddress.ip_address(str(item.get("ip_address") or ""))
        except ValueError:
            continue
        port = item.get("port")
        malware = _safe(item.get("malware"), 80)
        if not address.is_global or address.version != 4 or not malware or str(address) in seen:
            continue
        if not isinstance(port, int) or not 1 <= port <= 65535:
            port = None
        country = str(item.get("country") or "").upper()
        status = str(item.get("status") or "").lower()
        seen.add(str(address))
        rows.append({
            "kind": "botnet_c2",
            "indicator_type": "ipv4",
            "indicator": str(address),
            "port": port,
            "category": "botnet_c2",
            "country_code": country if _COUNTRY.fullmatch(country) else None,
            "first_seen": _day(item.get("first_seen")),
            "last_seen": _day(item.get("last_online")),
            "detail": malware + (f" · {status}" if status in {"online", "offline"} else ""),
            "rank": len(rows) + 1,
            "reference_url": "https://feodotracker.abuse.ch/",
            "metadata_safe": {"malware_family": malware, "status": status if status in {"online", "offline"} else None, "as_name": _safe(item.get("as_name"), 80)},
        })
        if len(rows) >= MAX_ROWS:
            break
    return rows


def parse_urlhaus(payload: bytes) -> list[dict]:
    """Recent malware-distribution URLs. No country is supplied, so these never draw on the map."""
    document = _load(payload)
    if isinstance(document, dict) and "query_status" in document:
        # API shape: {"query_status": "ok", "urls": [...]}.
        if document.get("query_status") not in {"ok", "no_results"}:
            raise ObservatoryError("unauthorized" if "auth" in str(document.get("query_status")).lower() else "schema_drift")
        items = document.get("urls") or []
        if not isinstance(items, list):
            raise ObservatoryError("schema_drift")
    elif isinstance(document, dict):
        items = [entry for value in document.values() for entry in (value if isinstance(value, list) else [value])]
    elif isinstance(document, list):
        items = document
    else:
        raise ObservatoryError("schema_drift")
    rows: list[dict] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        parsed = urllib.parse.urlsplit(str(item.get("url") or "").strip())
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
            continue
        try:
            valid = ipaddress.ip_address(host).is_global
        except ValueError:
            valid = _DOMAIN.fullmatch(host) is not None
        threat = _safe(item.get("threat"), 60)
        if not valid or not threat:
            continue
        safe = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path[:160] or "/", "", ""))
        if len(safe) > 300 or safe in seen:
            continue
        status = str(item.get("url_status") or "").lower()
        seen.add(safe)
        rows.append({
            "kind": "malware_distribution",
            "indicator_type": "url",
            "indicator": safe,
            "port": parsed.port,
            "category": threat,
            "country_code": None,
            "first_seen": _day(item.get("dateadded") or item.get("date_added")),
            "last_seen": _day(item.get("last_online") or item.get("dateadded") or item.get("date_added")),
            "detail": f"{threat.replace('_', ' ')}" + (f" · {status}" if status in {"online", "offline"} else ""),
            "rank": len(rows) + 1,
            "reference_url": "https://urlhaus.abuse.ch/",
            "metadata_safe": {"threat_type": threat, "status": status if status in {"online", "offline"} else None},
        })
        if len(rows) >= MAX_ROWS:
            break
    return rows


PARSERS = {"feodo": parse_feodo, "urlhaus": parse_urlhaus}
