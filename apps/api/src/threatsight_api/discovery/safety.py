from __future__ import annotations

import ipaddress
import time
from urllib.parse import ParseResult, urlparse

from threatsight_api.config import Settings

_MAX_SCANS_PER_MINUTE = 20
_scan_times: list[float] = []

ALLOWED_PORTS = {80, 443, 8091}
DEMO_HOSTS = frozenset({"demo-site"})


class DiscoverySafetyError(RuntimeError):
    def __init__(self, message: str, status_code: int = 403) -> None:
        super().__init__(message)
        self.status_code = status_code


def allowlist_hosts(settings: Settings) -> set[str]:
    hosts: set[str] = set(DEMO_HOSTS)
    parsed = urlparse(settings.demo_site_url)
    if parsed.hostname:
        hosts.add(parsed.hostname.lower())
    extra = getattr(settings, "discovery_allowlist", "") or ""
    for item in extra.split(","):
        host = item.strip().lower()
        if host:
            hosts.add(host)
    return hosts


def allowed_ports(settings: Settings) -> set[int]:
    ports = set(ALLOWED_PORTS)
    parsed = urlparse(settings.demo_site_url)
    if parsed.port:
        ports.add(parsed.port)
    return ports


def normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    netloc = parsed.netloc.lower()
    return f"{parsed.scheme}://{netloc}{path}"


def origin_of(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc.lower()}"


def assert_scan_allowed(settings: Settings, *, confirm_execution: bool) -> None:
    if settings.kill_switch:
        raise DiscoverySafetyError("Kill switch is engaged; discovery fetch is refused")
    if not settings.sandbox_default:
        raise DiscoverySafetyError("Discovery fetch requires sandbox_default=true")
    if not confirm_execution:
        raise DiscoverySafetyError("Explicit confirm_execution is required", 400)
    _assert_rate_limit()


def assert_url_allowed(url: str, settings: Settings) -> ParseResult:
    if not url or len(url) > 500:
        raise DiscoverySafetyError("URL is missing or too long", 400)
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise DiscoverySafetyError("URL scheme is not allowed", 400)
    if parsed.username or parsed.password:
        raise DiscoverySafetyError("URLs with credentials are not allowed", 400)
    host = (parsed.hostname or "").lower()
    if not host:
        raise DiscoverySafetyError("URL host is required", 400)
    try:
        ipaddress.ip_address(host)
        raise DiscoverySafetyError("IP-literal hosts are not allowed", 400)
    except ValueError:
        pass
    if host not in allowlist_hosts(settings):
        raise DiscoverySafetyError("Host is not on the discovery allow-list", 403)
    if parsed.port and parsed.port not in allowed_ports(settings):
        raise DiscoverySafetyError("Port is not allowed", 400)
    return parsed


def _assert_rate_limit() -> None:
    now = time.monotonic()
    cutoff = now - 60
    _scan_times[:] = [stamp for stamp in _scan_times if stamp > cutoff]
    if len(_scan_times) >= _MAX_SCANS_PER_MINUTE:
        raise DiscoverySafetyError("Discovery fetch rate limit exceeded", 429)
    _scan_times.append(now)
