"""Strict single-IP GreyNoise Community lookup client."""

from __future__ import annotations

from datetime import date
import ipaddress
import json
from pathlib import Path
import re
import stat
import urllib.error
import urllib.parse
import urllib.request

from threatsight_api.observatory.contract import ObservatoryError

HOST = "api.greynoise.io"
PREFIX = "/v3/community/"
MAX_RESPONSE = 64_000
_SAFE = re.compile(r"^[\w .:/,+()#@'-]{0,300}$")


def public_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ObservatoryError("invalid_ip") from exc
    if address.version != 4 or not address.is_global:
        raise ObservatoryError("invalid_ip")
    return str(address)


def read_api_key(path: str) -> str:
    target = Path(path)
    try:
        info = target.lstat()
    except OSError as exc:
        raise ObservatoryError("credential_unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ObservatoryError("credential_rejected")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_IROTH):
        raise ObservatoryError("credential_permissions")
    value = target.read_text(encoding="utf-8").strip()
    if not 16 <= len(value) <= 512 or any(char.isspace() for char in value):
        raise ObservatoryError("credential_rejected")
    return value


def fetch(ip: str, *, api_key_file: str = "", opener=None) -> bytes:
    address = public_ipv4(ip)
    endpoint = f"https://{HOST}{PREFIX}{address}"
    headers = {
        "Accept": "application/json",
        "User-Agent": "ThreatSight/1.0 (+https://threatsight.io)",
    }
    if api_key_file:
        headers["key"] = read_api_key(api_key_file)
    request = urllib.request.Request(endpoint, headers=headers, method="GET")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ObservatoryError("redirect_rejected")

    active = opener or urllib.request.build_opener(_NoRedirect)
    try:
        response = active.open(request, timeout=15)
    except ObservatoryError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ObservatoryError("not_found") from exc
        code = (
            "unauthorized"
            if exc.code in {401, 403}
            else "rate_limited"
            if exc.code == 429
            else "http_status"
        )
        raise ObservatoryError(code) from exc
    except Exception as exc:
        raise ObservatoryError("request_failed") from exc
    final = urllib.parse.urlparse(response.geturl())
    if (
        final.scheme != "https"
        or final.hostname != HOST
        or final.path != f"{PREFIX}{address}"
    ):
        raise ObservatoryError("redirect_rejected")
    payload = response.read(MAX_RESPONSE + 1)
    if len(payload) > MAX_RESPONSE:
        raise ObservatoryError("response_too_large")
    return payload


def parse(payload: bytes, expected_ip: str) -> dict:
    address = public_ipv4(expected_ip)
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObservatoryError("schema_drift") from exc
    if not isinstance(document, dict) or document.get("ip") != address:
        raise ObservatoryError("schema_drift")
    classification = str(document.get("classification") or "unknown").lower()
    if classification not in {"benign", "malicious", "unknown"}:
        raise ObservatoryError("schema_drift")
    result = {
        "noise": document.get("noise")
        if isinstance(document.get("noise"), bool)
        else None,
        "riot": document.get("riot")
        if isinstance(document.get("riot"), bool)
        else None,
        "classification": classification,
        "name": _safe(document.get("name"), 200),
        "provider": _safe(
            document.get("metadata", {}).get("organization")
            if isinstance(document.get("metadata"), dict)
            else "",
            200,
        ),
        "reference_url": _link(document.get("link")),
        "last_seen": _day(document.get("last_seen")),
        "message": _safe(document.get("message"), 300),
    }
    return result


def _safe(value: object, maximum: int) -> str:
    text = str(value or "").strip()[:maximum]
    return text if _SAFE.fullmatch(text) else ""


def _link(value: object) -> str:
    parsed = urllib.parse.urlparse(str(value or ""))
    return (
        str(value)[:500]
        if parsed.scheme == "https"
        and parsed.hostname in {"viz.greynoise.io", "www.greynoise.io"}
        else ""
    )


def _day(value: object) -> date | None:
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None
