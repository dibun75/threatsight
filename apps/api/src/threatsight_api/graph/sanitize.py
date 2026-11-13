"""Sanitize labels and attributes. Identifiers with controls are rejected."""

from __future__ import annotations

import json
import re

from threatsight_api.graph.bounds import MAX_ATTRIBUTE_BYTES, MAX_ID, MAX_LABEL

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")
_KEY = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_IDENTIFIER_KEYS = frozenset({
    "associated_resource_id",
    "principal_id",
    "role_id",
    "group_id",
    "member_id",
    "site_key",
})
_IDENTIFIER_LISTS = frozenset({"reference_ids"})
_DROPPED = frozenset({
    "verdict",
    "exposure",
    "exposed",
    "exploitable",
    "compromised",
    "reachable",
    "vulnerable",
    "safe",
    "unsafe",
    "control_effective",
    "internet_exposed",
})


class GraphFailure(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require_identifier(value: object, *, max_len: int = MAX_ID) -> str:
    text = str(value or "")
    if not text or len(text) > max_len or _CONTROL.search(text):
        raise GraphFailure("source_rejected")
    return text


def plain_text(value: object) -> str:
    return "".join(ch for ch in str(value or "") if ch.isprintable() and ch not in "<>")


def plain_payload(value: object) -> object:
    if isinstance(value, str):
        return plain_text(value)
    if isinstance(value, list):
        return [plain_payload(item) for item in value]
    if isinstance(value, dict):
        return {plain_text(key): plain_payload(item) for key, item in value.items()}
    return value


def clean_label(value: object) -> str:
    text = _CONTROL.sub(" ", str(value or ""))
    text = text.replace("<", " ").replace(">", " ")
    text = " ".join(text.split())[:MAX_LABEL]
    return text or "unnamed"


def clean_token(value: object, *, default: str) -> str:
    text = str(value or "").strip().lower()
    if _TOKEN.fullmatch(text):
        return text
    return default


def clean_attributes(value: object) -> tuple[dict, list[str]]:
    limitations: list[str] = []
    if not isinstance(value, dict):
        return {}, ["attributes_rejected"]
    cleaned: dict = {}
    for raw_key, raw_item in value.items():
        key = str(raw_key)
        if key in _DROPPED or not _KEY.fullmatch(key):
            limitations.append("attribute_dropped")
            continue
        cleaned[key] = _clean_value(raw_item, key)
    encoded = json.dumps(cleaned, sort_keys=True, default=str).encode()
    if len(encoded) > MAX_ATTRIBUTE_BYTES:
        raise GraphFailure("bound_exceeded")
    return cleaned, limitations


def _identifier(value: object) -> str:
    text = str(value or "")
    if not text or len(text) > MAX_ID or _CONTROL.search(text) or "<" in text or ">" in text:
        raise GraphFailure("source_rejected")
    return text


def _clean_value(value: object, key: str | None = None) -> object:
    if key in _IDENTIFIER_KEYS:
        if value in (None, ""):
            return ""
        return _identifier(value)
    if key in _IDENTIFIER_LISTS:
        if not isinstance(value, list):
            raise GraphFailure("source_rejected")
        return [_identifier(item) for item in value[:20]]
    if isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return clean_label(value)
    if isinstance(value, list):
        return [_clean_value(item) for item in value[:20]]
    if isinstance(value, dict):
        nested, _ = clean_attributes(value)
        return nested
    return clean_label(value)
