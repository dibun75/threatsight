"""Live Junos collection is opt-in and has no SSH client in this build."""

from __future__ import annotations

import json
import os
import re

from threatsight_api.connectors.junos.bounds import LOCATOR, CollectionFailure
from threatsight_api.connectors.junos.target import (
    accept_algorithm,
    approved_endpoint,
    ignored_proxy_environment,
)

_USERNAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def live_enabled() -> bool:
    return os.environ.get("THREATSIGHT_JUNOS_LIVE", "").strip().lower() in {"1", "true", "yes"}


def _credential_rejected(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"username", "private_key"}:
        return True
    username = value.get("username")
    key = value.get("private_key")
    if not isinstance(username, str) or _USERNAME.fullmatch(username) is None:
        return True
    if not isinstance(key, str) or len(key) < 64 or len(key) > 16_384:
        return True
    lowered = key.lower()
    if any(marker in lowered for marker in ("placeholder", "changeme", "example", "password", "secret")):
        return True
    first = key.splitlines()[0] if key.splitlines() else ""
    if not first.startswith("-----BEGIN ") or "PRIVATE KEY-----" not in first or "ENCRYPTED" in first:
        return True
    return not key.rstrip().endswith("-----")


def resolve_credential(locator: str) -> None:
    """Validate a runner-local credential and drop it. The key is never returned."""
    if not live_enabled():
        raise CollectionFailure("live_disabled")
    if not isinstance(locator, str) or LOCATOR.fullmatch(locator) is None:
        raise CollectionFailure("secret_unavailable")
    raw = os.environ.get("THREATSIGHT_JUNOS_CREDENTIALS", "")
    try:
        mapping = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        raise CollectionFailure("secret_unavailable") from None
    material = mapping.get(locator) if isinstance(mapping, dict) else None
    if _credential_rejected(material):
        raise CollectionFailure("secret_refused")


def open_session(configuration: dict, resolver=None) -> None:
    """Validate the approved target, then refuse to dial. No socket is opened."""
    ignored_proxy_environment(os.environ)
    approved_endpoint(configuration, resolver)
    if configuration.get("host_key_algorithm"):
        accept_algorithm(configuration.get("host_key_algorithm"))
    raise CollectionFailure("live_transport_unavailable")


class ClosedTransport:
    """Placeholder used if live dispatch is bypassed. It cannot dial a device."""

    def start(self, configuration: dict) -> None:
        del configuration
        raise CollectionFailure("live_transport_unavailable")

    def rpc(self, operation: str) -> bytes:
        del operation
        raise CollectionFailure("live_transport_unavailable")

    def observed_at(self):
        return None

    def presented_fingerprint(self) -> str:
        return ""
