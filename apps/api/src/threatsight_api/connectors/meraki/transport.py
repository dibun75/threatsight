"""GET-only Meraki transport. Redirects are refused."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from threatsight_api.connectors.meraki.bounds import (
    MAX_RESPONSE_BYTES,
    CollectionFailure,
    approved_url,
)
from threatsight_api.connectors.microsoft.bounds import MAX_ATTEMPTS

ALLOWED_METHODS = frozenset({"GET"})


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ValueError("redirect refused")


@dataclass(frozen=True)
class VendorRequest:
    method: str
    url: str


@dataclass(frozen=True)
class VendorResponse:
    status: int
    headers: dict[str, str]
    payload: list | dict | None = None
    byte_length: int = 0
    malformed: bool = False


class Transport(Protocol):
    def send_once(self, request: VendorRequest, token: str) -> VendorResponse:
        """Perform one approved request."""


def pause(seconds: float) -> None:
    time.sleep(min(2.0, max(0.0, seconds)))


def decode_payload(raw: bytes) -> list | dict | None:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CollectionFailure("response_too_large")
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise CollectionFailure("malformed_response") from None
    if not isinstance(parsed, list | dict):
        raise CollectionFailure("malformed_response")
    return parsed


def transmit(transport: Transport, request: VendorRequest, token: str, sleep=pause) -> VendorResponse:
    if request.method not in ALLOWED_METHODS:
        raise CollectionFailure("destination_refused")
    if token and any(ord(ch) < 32 or ch.isspace() for ch in token):
        raise CollectionFailure("destination_refused")
    from threatsight_api.connectors.meraki.live import collection_origin

    approved_url(request.url, origin=collection_origin())
    for attempt in range(MAX_ATTEMPTS):
        response = transport.send_once(request, token)
        if response.malformed:
            raise CollectionFailure("malformed_response")
        if response.byte_length > MAX_RESPONSE_BYTES:
            raise CollectionFailure("response_too_large")
        if response.status in {301, 302, 303, 307, 308}:
            raise CollectionFailure("redirect_refused")
        if response.status not in {500, 502, 503, 504}:
            return response
        if attempt + 1 == MAX_ATTEMPTS:
            break
        sleep(min(2.0, 0.2 * (attempt + 1)))
    raise CollectionFailure("transient_failure", True)


def open_vendor(method: str, url: str, headers: dict[str, str]) -> VendorResponse:
    opener = urllib.request.build_opener(_RejectRedirect)
    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        with opener.open(request, timeout=20) as response:
            status, raw, header_items = response.status, response.read(MAX_RESPONSE_BYTES + 1), response.headers.items()
    except ValueError:
        raise CollectionFailure("redirect_refused") from None
    except urllib.error.HTTPError as exc:
        status, raw, header_items = exc.code, exc.read(MAX_RESPONSE_BYTES + 1), exc.headers.items()
    except urllib.error.URLError:
        raise CollectionFailure("vendor_unavailable", True) from None
    lowered = {str(key).lower(): str(value) for key, value in header_items}
    if len(raw) > MAX_RESPONSE_BYTES:
        return VendorResponse(status, lowered, byte_length=len(raw))
    try:
        payload = decode_payload(raw)
    except CollectionFailure as exc:
        if exc.code == "malformed_response":
            return VendorResponse(status, lowered, malformed=True, byte_length=len(raw))
        raise
    return VendorResponse(status, lowered, payload, len(raw))


class LiveTransport:
    """Opt-in Dashboard client. It never follows redirects."""

    def __init__(self, opener=open_vendor, sleep=None) -> None:
        self._opener = opener
        self._sleep = sleep

    def send_once(self, request: VendorRequest, token: str) -> VendorResponse:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self._opener(request.method, request.url, headers)
