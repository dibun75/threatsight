"""Shared bounds for the Azure and Entra reference connectors."""

from __future__ import annotations

import json
import re
import uuid
from urllib.parse import parse_qs, urlsplit

MAX_RESPONSE_BYTES = 1_048_576
MAX_BODY_BYTES = 65_536
MAX_PAGES = 10
MAX_RECORDS = 500
MAX_ATTEMPTS = 3
ARM_API = "2024-04-01"
ROLE_API = "2022-04-01"

SECRET_FIELDS = frozenset({
    "secret", "token", "password", "credential", "api_key", "private_key",
    "authorization", "access_token", "client_secret", "bearer",
})
SEGMENT = re.compile(r"^[A-Za-z0-9._()-]{1,80}$")
SKIP_TOKEN = re.compile(r"^[A-Za-z0-9._~+=-]{1,2000}$")
CURSOR = re.compile(r"^[0-9]{1,2}\.[0-9]{1,4}$")
HOSTS = {
    "arm": "management.azure.com",
    "graph": "graph.microsoft.com",
    "login": "login.microsoftonline.com",
}


class CollectionFailure(Exception):
    def __init__(self, code: str, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class Interrupted(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def safe_label(value: object, limit: int = 80) -> str:
    text = "".join(ch if ch.isprintable() and ch not in "\r\n\t" else " " for ch in str(value or ""))
    return " ".join(text.split())[:limit]


def credential_refused(value: object) -> bool:
    if not isinstance(value, str):
        return True
    stripped = value.strip()
    if stripped != value or len(stripped) < 20 or len(stripped) > 4096:
        return True
    if any(ch.isspace() or ord(ch) < 32 for ch in stripped):
        return True
    normalized = stripped.lower()
    markers = ("changeme", "placeholder", "example", "password", "secret", "token", "fixture")
    return normalized in markers or any(normalized.startswith(f"{item}-") or normalized.startswith(f"{item}_") for item in markers)


def clean_arm_id(value: object) -> str | None:
    text = str(value or "")
    if not text.startswith("/subscriptions/") or len(text) > 500 or any(ord(ch) < 32 for ch in text):
        return None
    parts = text.split("/")
    if len(parts) < 3 or parts[0] != "" or parts[1] != "subscriptions":
        return None
    try:
        uuid.UUID(parts[2])
    except ValueError:
        return None
    if any(not SEGMENT.fullmatch(part) for part in parts[3:]):
        return None
    return text


def clean_tags(raw: object) -> dict[str, str]:
    if not isinstance(raw, str) or not raw or raw == "null":
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    cleaned: dict[str, str] = {}
    for key, value in list(parsed.items())[:20]:
        label = safe_label(key, 40).lower().replace(" ", "_")
        if not label or label in SECRET_FIELDS or label.startswith("bearer"):
            continue
        text = safe_label(value, 80)
        if not text or text.lower().startswith("bearer "):
            continue
        cleaned[label] = text
    return cleaned


def approved_url(url: str, family: str) -> str:
    parsed = urlsplit(url)
    host = HOSTS.get(family)
    if (
        parsed.scheme != "https"
        or parsed.hostname != host
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        raise CollectionFailure("destination_refused")
    if family == "login":
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 4 or parts[1:] != ["oauth2", "v2.0", "token"]:
            raise CollectionFailure("destination_refused")
        try:
            uuid.UUID(parts[0])
        except ValueError:
            raise CollectionFailure("destination_refused") from None
    elif family == "graph" and not parsed.path.startswith("/v1.0/"):
        raise CollectionFailure("destination_refused")
    elif family == "arm" and parsed.path in {"", "/"}:
        raise CollectionFailure("destination_refused")
    return url


def continuation_rejected(value: object) -> bool:
    return not isinstance(value, str) or SKIP_TOKEN.fullmatch(value) is None or "://" in value


def graph_next_rejected(url: object, select: frozenset[str]) -> bool:
    if not isinstance(url, str):
        return True
    try:
        approved_url(url, "graph")
    except CollectionFailure:
        return True
    fields = set(parse_qs(urlsplit(url).query).get("$select", [""])[0].split(","))
    return not fields or not fields <= select


def bounded_body(value: dict) -> None:
    if len(json.dumps(value, separators=(",", ":")).encode()) > MAX_BODY_BYTES:
        raise CollectionFailure("request_too_large")
