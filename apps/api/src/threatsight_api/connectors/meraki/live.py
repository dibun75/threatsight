"""Live Meraki collection is opt-in and disabled unless explicitly configured."""

from __future__ import annotations

import json
import os

from threatsight_api.connectors.meraki.bounds import ORIGIN, CollectionFailure, credential_refused


def live_enabled() -> bool:
    return os.environ.get("THREATSIGHT_MERAKI_LIVE", "").strip().lower() in {"1", "true", "yes"}


def collection_origin() -> str:
    override = os.environ.get("THREATSIGHT_MERAKI_TEST_ORIGIN", "").strip()
    if not override:
        return ORIGIN
    if os.environ.get("THREATSIGHT_ENV", "development").strip().lower() not in {"development", "test"}:
        raise CollectionFailure("destination_refused")
    from urllib.parse import urlsplit

    parsed = urlsplit(override)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise CollectionFailure("destination_refused")
    if parsed.port is None:
        return "http://127.0.0.1"
    return f"http://127.0.0.1:{parsed.port}"


def resolve_api_key(locator: str) -> str:
    if not live_enabled():
        raise CollectionFailure("live_disabled")
    raw = os.environ.get("THREATSIGHT_MERAKI_CREDENTIALS", "")
    try:
        mapping = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        raise CollectionFailure("secret_unavailable") from None
    value = mapping.get(locator) if isinstance(mapping, dict) else None
    secret = value.get("api_key") if isinstance(value, dict) else None
    if credential_refused(secret):
        raise CollectionFailure("secret_refused")
    return str(secret)
