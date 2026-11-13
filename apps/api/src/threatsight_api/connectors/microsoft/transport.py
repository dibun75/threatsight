"""Vendor transport. Callers can send only approved methods and hosts."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from threatsight_api.connectors.microsoft.bounds import (
    MAX_ATTEMPTS,
    MAX_RESPONSE_BYTES,
    CollectionFailure,
    approved_url,
    bounded_body,
)

ALLOWED_QUERIES: set[str] = set()


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ValueError("redirect refused")


@dataclass(frozen=True)
class VendorRequest:
    method: str
    url: str
    family: str
    json_body: dict | None = None


@dataclass(frozen=True)
class VendorResponse:
    status: int
    headers: dict[str, str]
    payload: dict | None


class Transport(Protocol):
    def send_once(self, request: VendorRequest, token: str) -> VendorResponse:
        """Perform one approved request and return a bounded response."""


def register_queries(queries: set[str]) -> None:
    ALLOWED_QUERIES.update(queries)


def pause(seconds: float) -> None:
    time.sleep(min(2.0, max(0.0, seconds)))


def transmit(transport: Transport, request: VendorRequest, token: str, sleep=pause) -> VendorResponse:
    if request.method not in {"GET", "POST"} or (token and any(ord(ch) < 32 or ch.isspace() for ch in token)):
        raise CollectionFailure("destination_refused")
    approved_url(request.url, request.family)
    if request.json_body is not None:
        bounded_body(request.json_body)
        query = request.json_body.get("query")
        if query is not None and query not in ALLOWED_QUERIES:
            raise CollectionFailure("query_rejected")
    for attempt in range(MAX_ATTEMPTS):
        response = transport.send_once(request, token)
        if response.status not in {500, 502, 503, 504}:
            return response
        if attempt + 1 == MAX_ATTEMPTS:
            break
        sleep(min(2.0, 0.2 * (attempt + 1)))
    raise CollectionFailure("transient_failure", True)


def _payload(raw: bytes) -> dict | None:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CollectionFailure("response_too_large")
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise CollectionFailure("malformed_response") from None
    if not isinstance(parsed, dict):
        raise CollectionFailure("malformed_response")
    return parsed


def open_vendor(method: str, url: str, body: bytes | None, headers: dict[str, str]) -> VendorResponse:
    opener = urllib.request.build_opener(_RejectRedirect)
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(request, timeout=20) as response:
            status, raw, header_items = response.status, response.read(MAX_RESPONSE_BYTES + 1), response.headers.items()
    except ValueError:
        raise CollectionFailure("redirect_refused") from None
    except urllib.error.HTTPError as exc:
        status, raw, header_items = exc.code, exc.read(MAX_RESPONSE_BYTES + 1), exc.headers.items()
    except urllib.error.URLError:
        raise CollectionFailure("vendor_unavailable", True) from None
    return VendorResponse(status, {str(key).lower(): str(value) for key, value in header_items}, _payload(raw))


class LiveTransport:
    """Opt-in client-credentials transport. It never follows redirects."""

    def __init__(self, opener=open_vendor, sleep=None) -> None:
        self._opener = opener
        self._sleep = sleep

    def authorize(self, tenant_id: str, client_id: str, client_secret: str, scope: str) -> str:
        from threatsight_api.connectors.microsoft.live import live_enabled

        if not live_enabled():
            raise CollectionFailure("live_disabled")
        url = approved_url(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            "login",
        )
        body = urllib.parse.urlencode({
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
            "grant_type": "client_credentials",
        }).encode()
        response = self._opener("POST", url, body, {"Content-Type": "application/x-www-form-urlencoded"})
        token = response.payload.get("access_token") if response.status == 200 and response.payload else None
        if not isinstance(token, str):
            raise CollectionFailure("token_request_failed", response.status >= 500)
        return token

    def send_once(self, request: VendorRequest, token: str) -> VendorResponse:
        body = None if request.json_body is None else json.dumps(request.json_body).encode()
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self._opener(request.method, request.url, body, headers)
