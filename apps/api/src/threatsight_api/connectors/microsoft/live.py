"""Live Microsoft collection is opt-in and disabled unless explicitly configured."""

from __future__ import annotations

import json
import os
import uuid

from threatsight_api.connectors.microsoft.bounds import CollectionFailure, credential_refused

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def live_enabled() -> bool:
    return os.environ.get("THREATSIGHT_MICROSOFT_LIVE", "").strip().lower() in {"1", "true", "yes"}


def resolve_credential(locator: str) -> tuple[str, str]:
    if not live_enabled():
        raise CollectionFailure("live_disabled")
    raw = os.environ.get("THREATSIGHT_MICROSOFT_CREDENTIALS", "")
    try:
        mapping = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        raise CollectionFailure("secret_unavailable") from None
    value = mapping.get(locator) if isinstance(mapping, dict) else None
    if not isinstance(value, dict):
        raise CollectionFailure("secret_unavailable")
    try:
        client_id = str(uuid.UUID(str(value.get("client_id", ""))))
    except ValueError:
        raise CollectionFailure("secret_unavailable") from None
    secret = value.get("client_secret")
    if credential_refused(secret):
        raise CollectionFailure("secret_refused")
    return client_id, str(secret)
