"""SSH target policy. These checks do not open a socket."""

from __future__ import annotations

import hmac
import ipaddress
import os
from collections.abc import Callable

from threatsight_api.connectors.junos.bounds import (
    ACCEPTED_ALGORITHMS,
    DNS_TIMEOUT_SECONDS,
    FINGERPRINT,
    HOSTNAME,
    MAX_CONNECT_ATTEMPTS,
    METADATA_HOSTS,
    SESSION_SECONDS,
    CollectionFailure,
)

Resolver = Callable[[str], list[str]]
_PROXY_KEYS = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"})


def ignored_proxy_environment(environ: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if environ is None else environ
    return {key: value for key, value in source.items() if key not in _PROXY_KEYS}


def default_resolver(host: str) -> list[str]:
    del host
    raise CollectionFailure("dns_resolution_unavailable")


def accept_algorithm(name: object) -> None:
    if name not in ACCEPTED_ALGORITHMS:
        raise CollectionFailure("ssh_algorithm_rejected")


def host_key_accepted(pinned: object, presented: object) -> None:
    if not isinstance(pinned, str) or FINGERPRINT.fullmatch(pinned) is None:
        raise CollectionFailure("host_key_required")
    if not isinstance(presented, str) or FINGERPRINT.fullmatch(presented) is None or not hmac.compare_digest(pinned, presented):
        raise CollectionFailure("host_key_mismatch")


def approved_port(port: object, override: object) -> int:
    if port == 830:
        return 830
    if override is True and isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
        return port
    raise CollectionFailure("destination_refused")


def _reject_ip(value: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if value.version != 4 or value.is_multicast or value.is_unspecified or value.is_loopback or value.is_link_local:
        raise CollectionFailure("destination_refused")


def pin_address(host: str, resolver: Resolver) -> str:
    first = resolver(host)
    second = resolver(host)
    if not isinstance(first, list) or first != second or len(first) != 1 or not isinstance(first[0], str):
        raise CollectionFailure("dns_rebinding")
    try:
        parsed = ipaddress.ip_address(first[0])
    except ValueError:
        raise CollectionFailure("dns_rebinding") from None
    _reject_ip(parsed)
    return str(parsed)


def approved_endpoint(configuration: dict, resolver: Resolver | None = None) -> str:
    host = str(configuration.get("target_host") or "").lower()
    approved_port(configuration.get("port", 830), configuration.get("port_override"))
    if host in METADATA_HOSTS or not host:
        raise CollectionFailure("destination_refused")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        _reject_ip(literal)
        return str(literal)
    if HOSTNAME.fullmatch(host) is None:
        raise CollectionFailure("destination_refused")
    return pin_address(host, resolver or default_resolver)


def connect_with_retry(opener: Callable[[], None], sleep: Callable[[float], None]) -> None:
    last: CollectionFailure | None = None
    for attempt in range(MAX_CONNECT_ATTEMPTS):
        try:
            opener()
            return
        except CollectionFailure as exc:
            last = exc
            if exc.code not in {"connection_timeout", "connection_failed"} or attempt + 1 == MAX_CONNECT_ATTEMPTS:
                raise
            sleep(min(1.0, 0.25 * (attempt + 1)))
    raise last or CollectionFailure("connection_failed")


def session_expired(started: float, now: float) -> bool:
    return now - started > SESSION_SECONDS


def dns_timeout_seconds() -> int:
    return DNS_TIMEOUT_SECONDS
