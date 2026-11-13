#!/usr/bin/env python3
"""Read-only checks for the public reference after local authentication.

No credentials, no writes, and no authenticated session. Exit 0 when every
check passes. Exit 1 when a check fails. Exit 2 on usage.
"""

from __future__ import annotations

import argparse
import sys
import time
import urllib.error
import urllib.request

PAGES = ("/", "/demo", "/threats", "/services", "/paths", "/controls", "/actions", "/evidence", "/briefing", "/tour")
HEADERS = (
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
)


class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, f"redirect to {newurl}", headers, fp)


def fetch(url: str, timeout: float) -> tuple[int, dict[str, str], bytes, float]:
    opener = urllib.request.build_opener(RefuseRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "ThreatSightPublicDemoMonitor/1.0"})
    started = time.monotonic()
    with opener.open(request, timeout=timeout) as response:
        body = response.read(200_000)
        elapsed = time.monotonic() - started
        headers = {key.lower(): value for key, value in response.headers.items()}
        return response.status, headers, body, elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Check anonymous protection on the public reference.")
    parser.add_argument("--origin", default="https://threatsight.io")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--max-seconds", type=float, default=8.0)
    args = parser.parse_args()
    origin = args.origin.rstrip("/")
    failed = False

    def report(name: str, ok: bool, detail: str) -> None:
        nonlocal failed
        failed = failed or not ok
        print(f"{'ok' if ok else 'FAIL'} {name} {detail}")

    for path in PAGES:
        started = time.monotonic()
        try:
            status, _headers, _body, elapsed = fetch(origin + path, args.timeout)
        except urllib.error.HTTPError as exc:
            elapsed = time.monotonic() - started
            location = exc.headers.get("Location") or ""
            safe = location.startswith("/login?return_to=") and "://" not in location.split("?", 1)[0]
            report(path, exc.code in {302, 303, 307, 308} and safe and elapsed <= args.max_seconds, f"{exc.code} {location} {elapsed:.2f}s")
            continue
        except Exception as exc:  # noqa: BLE001
            report(path, False, type(exc).__name__)
            continue
        report(path, False, f"unexpected {status}")

    try:
        status, headers, body, elapsed = fetch(origin + "/login", args.timeout)
        text = body.decode("utf-8", "replace")
        report(
            "login",
            status == 200
            and ("Sign in" in text or "Checking sign-in" in text)
            and "demo-viewer" not in text
            and "Command center" not in text
            and elapsed <= args.max_seconds,
            f"{status} {elapsed:.2f}s",
        )
        missing = [name for name in HEADERS if name not in headers]
        report("headers", not missing, ",".join(missing) or "present")
        cache = headers.get("cache-control", "")
        report("html-cache", "no-cache" in cache or "no-store" in cache, cache or "missing")
    except Exception as exc:  # noqa: BLE001
        report("login", False, type(exc).__name__)

    started = time.monotonic()
    try:
        status, headers, body, elapsed = fetch(origin + "/api/v1/ops/status", args.timeout)
    except urllib.error.HTTPError as exc:
        body = exc.read(20_000)
        status = exc.code
        headers = {key.lower(): value for key, value in exc.headers.items()}
        elapsed = time.monotonic() - started
    text = body.decode("utf-8", "replace")
    report("api-status", status == 401 and "demo-viewer" not in text, f"{status} {elapsed:.2f}s")
    report("api-cache", "no-store" in headers.get("cache-control", ""), headers.get("cache-control", "missing"))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL monitor {type(exc).__name__}")
        raise SystemExit(1) from None
