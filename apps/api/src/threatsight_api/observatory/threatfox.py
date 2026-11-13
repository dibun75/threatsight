"""Bounded ThreatFox recent-IOC client. Live use is commercially gated."""
from __future__ import annotations

from datetime import datetime
import ipaddress
import json
from pathlib import Path
import re
import stat
import urllib.error
import urllib.parse
import urllib.request

from threatsight_api.observatory.contract import ObservatoryError

HOST = "threatfox-api.abuse.ch"
PATH = "/api/v1/"
ENDPOINT = f"https://{HOST}{PATH}"
MAX_RESPONSE = 2_000_000
MAX_ROWS = 250
_SAFE = re.compile(r"^[\w .:/,+()#@'-]{1,300}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def read_auth_key(path: str) -> str:
    target = Path(path)
    try:
        info = target.lstat()
    except OSError as exc:
        raise ObservatoryError("credential_unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ObservatoryError("credential_rejected")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_IROTH):
        raise ObservatoryError("credential_permissions")
    try:
        value = target.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ObservatoryError("credential_unavailable") from exc
    if not 16 <= len(value) <= 512 or any(char.isspace() for char in value):
        raise ObservatoryError("credential_rejected")
    return value


def fetch_recent(token_file: str, *, days: int = 1, opener=None) -> bytes:
    if days not in range(1, 8):
        raise ObservatoryError("request_rejected")
    token = read_auth_key(token_file)
    body = json.dumps({"query": "get_iocs", "days": days}, separators=(",", ":")).encode()
    request = urllib.request.Request(
        ENDPOINT,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json", "Auth-Key": token, "User-Agent": "ThreatSight/1.0 (+https://threatsight.io)"},
        method="POST",
    )

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
    if final.scheme != "https" or final.hostname != HOST or final.path != PATH:
        raise ObservatoryError("redirect_rejected")
    payload = response.read(MAX_RESPONSE + 1)
    if len(payload) > MAX_RESPONSE:
        raise ObservatoryError("response_too_large")
    return payload


def parse_recent(payload: bytes) -> list[dict]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObservatoryError("schema_drift") from exc
    if not isinstance(document, dict) or document.get("query_status") != "ok" or not isinstance(document.get("data"), list):
        raise ObservatoryError("schema_drift")
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in document["data"]:
        if not isinstance(item, dict):
            continue
        ioc_type = str(item.get("ioc_type") or "").lower()
        indicator, port = _indicator(ioc_type, item.get("ioc"))
        if not indicator or (ioc_type, indicator) in seen:
            continue
        threat_type = _safe(item.get("threat_type"), 80)
        malware = _safe(item.get("malware_printable") or item.get("malware"), 120)
        confidence = item.get("confidence_level")
        if not threat_type or not malware or not isinstance(confidence, int) or not 0 <= confidence <= 100:
            continue
        seen.add((ioc_type, indicator))
        rows.append({
            "kind": "malware_infrastructure",
            "indicator_type": ioc_type,
            "indicator": indicator,
            "port": port,
            "category": threat_type,
            "first_seen": _day(item.get("first_seen")),
            "last_seen": _day(item.get("last_seen")),
            "detail": malware,
            "rank": len(rows) + 1,
            "reference_url": "https://threatfox.abuse.ch/",
            "metadata_safe": {"malware_family": malware, "threat_type": threat_type, "ioc_type": ioc_type, "confidence_score": confidence},
        })
        if len(rows) >= MAX_ROWS:
            break
    return rows


def _safe(value: object, maximum: int) -> str | None:
    text = str(value or "").strip()[:maximum]
    return text if text and _SAFE.fullmatch(text) else None


def _day(value: object) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S UTC").date().isoformat()
    except ValueError:
        return None


def _indicator(ioc_type: str, value: object) -> tuple[str | None, int | None]:
    raw = str(value or "").strip()
    if ioc_type == "ip:port":
        host, separator, raw_port = raw.rpartition(":")
        try:
            address, port = ipaddress.ip_address(host), int(raw_port)
        except ValueError:
            return None, None
        return (f"{address}:{port}", port) if separator and address.is_global and 1 <= port <= 65535 else (None, None)
    if ioc_type == "domain":
        domain = raw.lower().rstrip(".")
        return (domain, None) if _DOMAIN.fullmatch(domain) else (None, None)
    if ioc_type == "url":
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            return None, None
        host = parsed.hostname.lower()
        try:
            valid_host = ipaddress.ip_address(host).is_global
        except ValueError:
            valid_host = _DOMAIN.fullmatch(host) is not None
        if not valid_host:
            return None, None
        port = parsed.port
        path = parsed.path[:160] or "/"
        safe = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc.lower(), path, "", ""))
        return (safe, port) if len(safe) <= 300 else (None, None)
    return None, None
