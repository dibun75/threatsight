"""Minimal outbound-only customer runner process.

Vendor adapters plug into the versioned ConnectorContract. Until an adapter is
installed, claimed work is returned as explicitly unsupported.
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from threatsight_api.config import get_settings
from threatsight_api.connectors.microsoft.dispatch import execute_claimed

_running = True


def _stop(*_args) -> None:
    global _running
    _running = False


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.URLError("control-plane redirect refused")


def control_plane_base(value: str, *, require_tls: bool = False) -> str:
    parsed = urllib.parse.urlparse(value.strip())
    allowed = {"https"} if require_tls else {"http", "https"}
    if parsed.scheme not in allowed or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        requirement = "HTTPS" if require_tls else "HTTP(S)"
        raise ValueError(f"control-plane URL must be {requirement} without credentials")
    return value.strip().rstrip("/")


def load_runner_credential(environ: dict[str, str] | None = None) -> str:
    """Read the runner credential from a file. An environment variable is accepted only in development or test."""
    env = os.environ if environ is None else environ
    path = env.get("THREATSIGHT_RUNNER_CREDENTIAL_FILE", "").strip()
    if path:
        credential = Path(path).read_text(encoding="utf-8").strip()
        if not credential or "\x00" in credential:
            raise ValueError("runner credential file is empty")
        return credential
    mode = env.get("THREATSIGHT_ENV", "development").strip().lower()
    if mode in {"development", "test"}:
        return env.get("THREATSIGHT_RUNNER_CREDENTIAL", "").strip()
    raise ValueError("runner credential file is required outside development")


def _serve_health(port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b'{"status":"ok"}' if self.path == "/health" else b'{"status":"not_found"}'
            self.send_response(200 if self.path == "/health" else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def interpret_control_plane(status: int, body: dict | None) -> str:
    if status == 503:
        return "kill_switch"
    if status == 409:
        detail = str((body or {}).get("detail", "")).lower()
        return "cancelled" if "cancel" in detail else "lease_lost"
    if status >= 400:
        return "lease_lost"
    return "ok"


def _exchange(base: str, path: str, credential: str, body: dict | None = None) -> tuple[int, dict | None]:
    base = control_plane_base(base)
    request = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(body or {}).encode(),
        headers={"Authorization": f"Bearer {credential}", "Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(_RejectRedirect)
    try:
        with opener.open(request, timeout=15) as response:
            payload = response.read(1_000_000)
            parsed = json.loads(payload) if payload else None
            return response.status, parsed if isinstance(parsed, dict) else None
    except urllib.error.HTTPError as exc:
        raw = exc.read(1000)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        return exc.code, parsed if isinstance(parsed, dict) else None


def _post(base: str, path: str, credential: str, body: dict | None = None) -> dict | None:
    status, parsed = _exchange(base, path, credential, body)
    if status >= 400:
        raise urllib.error.URLError("control-plane request rejected")
    return parsed


def _finish(base: str, credential: str, job: dict) -> None:
    dispatch = job.get("dispatch") if isinstance(job.get("dispatch"), dict) else {}
    cache = {"state": "ok"}

    def read() -> None:
        status, body = _exchange(
            base, f"/api/v1/runner/v1/jobs/{job['id']}/progress", credential, {"progress": {"phase": "collection"}},
        )
        cache["state"] = interpret_control_plane(status, body)

    def disabled() -> bool:
        read()
        return get_settings().kill_switch or cache["state"] == "kill_switch"

    result = execute_claimed(
        job,
        str(dispatch.get("tenant_id", "")),
        str(dispatch.get("workspace_id", "")),
        disabled=disabled,
        cancelled=lambda: cache["state"] == "cancelled",
        lease_ok=lambda: cache["state"] == "ok",
    )
    if result["action"] == "complete":
        _post(base, f"/api/v1/runner/v1/jobs/{job['id']}/complete", credential, result["envelope"])
    elif result["action"] == "fail":
        _post(
            base, f"/api/v1/runner/v1/jobs/{job['id']}/fail", credential,
            {"code": result["code"], "detail": result["detail"], "retryable": result["retryable"]},
        )


def main() -> None:
    base = os.environ.get("THREATSIGHT_CONTROL_PLANE_URL", "").strip()
    mode = os.environ.get("THREATSIGHT_ENV", "development").strip().lower()
    try:
        credential = load_runner_credential()
        base = control_plane_base(base, require_tls=mode not in {"development", "test"})
    except (OSError, ValueError) as exc:
        raise SystemExit("runner configuration rejected") from exc
    if not base or not credential:
        raise SystemExit("control-plane URL and runner credential are required")
    health_port = os.environ.get("THREATSIGHT_RUNNER_HEALTH_PORT", "8092").strip()
    if health_port and health_port != "0":
        try:
            _serve_health(int(health_port))
        except (OSError, ValueError) as exc:
            raise SystemExit("runner configuration rejected") from exc
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while _running:
        if get_settings().kill_switch:
            time.sleep(get_settings().worker_poll_seconds)
            continue
        try:
            job = _post(base, "/api/v1/runner/v1/claim", credential)
            if job:
                _finish(base, credential, job)
            else:
                time.sleep(get_settings().worker_poll_seconds)
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
            time.sleep(min(30.0, get_settings().worker_poll_seconds * 2))


if __name__ == "__main__":
    main()
