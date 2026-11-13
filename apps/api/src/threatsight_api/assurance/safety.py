from __future__ import annotations

import time
from urllib.parse import urlparse

from threatsight_api.config import Settings

_MAX_RUNS_PER_MINUTE = 30
_run_times: list[float] = []


class AssuranceSafetyError(RuntimeError):
    def __init__(self, message: str, status_code: int = 403) -> None:
        super().__init__(message)
        self.status_code = status_code


def assert_execution_allowed(settings: Settings, *, confirm_execution: bool, target_url: str) -> None:
    if settings.kill_switch:
        raise AssuranceSafetyError("Kill switch is engaged; assurance execution is refused")
    if not settings.sandbox_default:
        raise AssuranceSafetyError("Assurance execution requires sandbox_default=true")
    if not confirm_execution:
        raise AssuranceSafetyError("Explicit confirm_execution is required", 400)
    allowed = _normalize(settings.demo_agent_url)
    requested = _normalize(target_url)
    if not allowed or requested != allowed:
        raise AssuranceSafetyError("Target is not on the demo-agent allow-list")
    parsed = urlparse(requested)
    if parsed.scheme not in {"http", "https"}:
        raise AssuranceSafetyError("Target URL scheme is not allowed")
    host = (parsed.hostname or "").lower()
    if host not in {"localhost", "127.0.0.1", "demo-agent"}:
        raise AssuranceSafetyError("Target host is not the synthetic demo agent")
    _assert_rate_limit()


def _assert_rate_limit() -> None:
    now = time.monotonic()
    cutoff = now - 60
    _run_times[:] = [stamp for stamp in _run_times if stamp > cutoff]
    if len(_run_times) >= _MAX_RUNS_PER_MINUTE:
        raise AssuranceSafetyError("Assurance execution rate limit exceeded", 429)
    _run_times.append(now)


def _normalize(url: str) -> str:
    return url.rstrip("/")
