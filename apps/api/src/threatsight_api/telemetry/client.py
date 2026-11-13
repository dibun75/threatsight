"""Bounded Cloudflare Radar client. Callers cannot supply a URL."""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request

from threatsight_api.telemetry.contract import RadarError

HOST = "api.cloudflare.com"
PATHS = {
    "timeseries": "/client/v4/radar/attacks/layer7/timeseries",
    "origin": "/client/v4/radar/attacks/layer7/top/locations/origin",
    "target": "/client/v4/radar/attacks/layer7/top/locations/target",
    "pairs": "/client/v4/radar/attacks/layer7/top/attacks",
    "mitigation": "/client/v4/radar/attacks/layer7/summary/mitigation_product",
}
WINDOWS = {"24h": "1d", "7d": "7d"}
TOKEN_PATH = "/run/secrets/cloudflare_radar_token"


def load_token(path: str, *, allowed_path: str = TOKEN_PATH) -> str:
    import os
    from pathlib import Path

    if os.path.abspath(path) != os.path.abspath(allowed_path):
        raise RadarError("token_path_rejected")
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise RadarError("token_path_rejected")
    info = file.stat()
    mode = info.st_mode & 0o777
    owner_only = mode == 0o600 and info.st_uid == os.getuid()
    group_read = mode == 0o640 and info.st_gid == os.getgid() and mode & 0o007 == 0
    if not owner_only and not group_read:
        raise RadarError("token_permissions")
    raw = file.read_bytes()
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RadarError("token_rejected") from exc
    if value.endswith("\n"):
        value = value[:-1]
    if not value or any(character in value for character in " \t\r\n"):
        raise RadarError("token_rejected")
    return value


def fetch_dataset(
    dataset: str,
    window: str,
    *,
    token: str,
    location: str | None = None,
    opener=None,
    sleeper=time.sleep,
) -> tuple[int, bytes]:
    if dataset not in PATHS or window not in WINDOWS or (location not in {None, "NO"}):
        raise RadarError("request_rejected")
    query = {"dateRange": WINDOWS[window], "format": "json"}
    # Top-location endpoints have no location filter. A bounded limit is the
    # official way to retain countries beyond Cloudflare's default five.
    if dataset in {"origin", "target"} and location is None:
        query["limit"] = "100"
    elif dataset == "pairs" and location is None:
        query["limit"] = "25"
    if location:
        query["location"] = location
    url = f"https://{HOST}{PATHS[dataset]}?{urllib.parse.urlencode(query)}"
    delay = 1.0
    last = RadarError("retries_exhausted")
    for _ in range(3):
        try:
            return _once(url, token=token, opener=opener)
        except RadarError as exc:
            last = exc
            if exc.code == "rate_limited":
                sleeper(min(_retry_after(exc), 30))
            elif exc.code in {"timeout", "http_status"}:
                sleeper(delay)
                delay = min(delay * 2, 8)
            else:
                raise
    raise last


def _retry_after(exc: RadarError) -> float:
    try:
        return float(getattr(exc, "retry_after", 1))
    except (TypeError, ValueError):
        return 1


def _once(url: str, *, token: str, opener) -> tuple[int, bytes]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != HOST or parsed.path not in PATHS.values():
        raise RadarError("request_rejected")
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}, method="GET")

    class _Guard(urllib.request.HTTPRedirectHandler):
        max_redirections = 2

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            target = urllib.parse.urlparse(newurl)
            if target.scheme != "https" or target.hostname != HOST:
                raise RadarError("redirect_rejected")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    active = opener or urllib.request.build_opener(_Guard)
    try:
        response = active.open(request, timeout=20)
    except RadarError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            error = RadarError("rate_limited")
            error.retry_after = exc.headers.get("Retry-After", "1") if exc.headers else "1"
            raise error from exc
        if exc.code in {401, 403}:
            raise RadarError("unauthorized") from exc
        if exc.code >= 500:
            raise RadarError("http_status") from exc
        raise RadarError("http_status") from exc
    except TimeoutError as exc:
        raise RadarError("timeout") from exc
    except Exception as exc:
        if "timed out" in str(exc).lower():
            raise RadarError("timeout") from exc
        raise RadarError("request_failed") from exc
    final = urllib.parse.urlparse(response.geturl())
    if final.scheme != "https" or final.hostname != HOST:
        raise RadarError("redirect_rejected")
    content_type = response.headers.get_content_type()
    if content_type != "application/json":
        raise RadarError("content_type")
    payload = response.read(1_000_001)
    if len(payload) > 1_000_000:
        raise RadarError("response_too_large")
    return response.status, payload
