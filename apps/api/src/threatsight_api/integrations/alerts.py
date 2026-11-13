"""Alerts out of ThreatSight: a webhook, Slack, Microsoft Teams or a SIEM (syslog with CEF).

An alert goes out when a readiness check returns its fail condition (``failed_by_defined_check``).
That outcome means the named check's fail condition was met. It is not a statement of compromise,
and the wording of every payload says so.

Destinations are kept per workspace. Webhook URLs carry their own secret, so views only return a
masked URL. Delivery runs on a background thread after the database transaction commits, so a slow
receiver never holds up a request. Each delivery is tried up to three times and its outcome is kept.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import socket
import threading
import time
import urllib.error
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import structlog
from sqlalchemy import event as sa_event
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.config import get_settings
from threatsight_api.persistence.integration_models import AlertDelivery, AlertDestination
from threatsight_api.persistence.session import SessionLocal
from threatsight_api.url_safety import open_unredirected

logger = structlog.get_logger("threatsight.alerts")

KINDS = ("webhook", "slack", "teams", "syslog")
ALERT_OUTCOMES = frozenset({"failed_by_defined_check"})
MAX_DESTINATIONS = 20
TRIES = 3
TIMEOUT = 10.0
VERSION = "1.0"
RETRY_WAIT = 2.0


@dataclass(frozen=True)
class Target:
    """A plain copy of a destination, safe to use on another thread."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    workspace_id: uuid.UUID
    kind: str
    label: str
    url: str | None
    secret: str | None
    host: str | None
    port: int | None
    protocol: str

    @classmethod
    def of(cls, row: AlertDestination) -> "Target":
        return cls(row.id, row.tenant_id, row.workspace_id, row.kind, row.label, row.url, row.secret, row.host, row.port, row.protocol)


def mask_url(url: str) -> str:
    """Show where a webhook goes without its secret path: https://hooks.slack.com/…a1b2"""
    parsed = urlparse(url)
    tail = url[-4:] if len(url) > 12 else ""
    return f"{parsed.scheme}://{parsed.hostname}{':' + str(parsed.port) if parsed.port else ''}/…{tail}"


def public_view(row: AlertDestination) -> dict[str, Any]:
    target = f"{row.protocol}://{row.host}:{row.port}" if row.kind == "syslog" else mask_url(row.url or "")
    return {
        "id": str(row.id), "kind": row.kind, "label": row.label, "target": target,
        "has_secret": bool(row.secret), "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def validate(body: dict[str, Any]) -> dict[str, Any]:
    """Check a new destination and return the column values. Raises ValueError with a plain reason."""
    kind = str(body.get("kind") or "")
    label = str(body.get("label") or "").strip()
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {list(KINDS)}")
    if not label or len(label) > 80:
        raise ValueError("give the destination a name of at most 80 characters")
    values: dict[str, Any] = {"kind": kind, "label": label}
    if kind == "syslog":
        host = str(body.get("host") or "").strip()
        protocol = str(body.get("protocol") or "udp").lower()
        try:
            port = int(body.get("port") or 514)
        except (TypeError, ValueError):
            raise ValueError("port must be a number") from None
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}|\[?[0-9a-fA-F:]{2,39}\]?", host):
            raise ValueError("syslog host must be a host name or IP address")
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if protocol not in {"udp", "tcp"}:
            raise ValueError("protocol must be udp or tcp")
        values.update(host=host.strip("[]"), port=port, protocol=protocol)
    else:
        url = str(body.get("url") or "").strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or len(url) > 1000 or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("URL must be an http(s) address without a user, password or fragment in it")
        if get_settings().is_production:
            from threatsight_api.url_safety import endpoint_problem

            problem = endpoint_problem(url)
            if problem:
                raise ValueError(f"URL {problem}")
        secret = str(body.get("secret") or "").strip() or None
        if secret is not None and (kind != "webhook" or len(secret) > 200):
            raise ValueError("a signing secret is only for plain webhooks, at most 200 characters")
        values.update(url=url, secret=secret)
    return values


# Event payloads ------------------------------------------------------------------------------

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def result_event(result: Any, check: Any, workspace_key: str | None) -> dict[str, Any]:
    return {
        "source": "threatsight",
        "version": VERSION,
        "type": "readiness.fail",
        "id": str(uuid.uuid4()),
        "time": _now(),
        "workspace": workspace_key,
        "result_id": str(result.id),
        "request_id": str(result.request_id),
        "check_id": result.check_id,
        "check_title": getattr(check, "title", None),
        "check_version": result.check_version,
        "verdict": "FAIL",
        "reason_code": result.outcome,
        "title": f"Readiness check failed: {getattr(check, 'title', result.check_id)}",
        "summary": result.summary,
        "maturity": result.maturity,
        "freshness": result.freshness,
        "evidence_hash": result.evidence_hash,
        "note": "The named check returned its fail condition. This is not a statement of compromise.",
    }


def ping_event() -> dict[str, Any]:
    return {
        "source": "threatsight", "version": VERSION, "type": "test", "id": str(uuid.uuid4()), "time": _now(),
        "verdict": "TEST", "reason_code": "TEST", "title": "ThreatSight test alert", "check_id": "TEST",
        "summary": "This is a test from the ThreatSight Integrations page. Real alerts arrive when a readiness check fails.",
    }


def _facts(event: dict[str, Any]) -> list[tuple[str, str]]:
    rows = [("Check", event.get("check_id")), ("Reason", event.get("reason_code")), ("Maturity", event.get("maturity")),
            ("Workspace", event.get("workspace")), ("Evidence", event.get("evidence_hash"))]
    return [(k, str(v)) for k, v in rows if v]


def _headline(event: dict[str, Any]) -> str:
    return f"ThreatSight {event.get('verdict')}: {event.get('title')}"


def slack_body(event: dict[str, Any]) -> dict[str, Any]:
    lines = [f"*{_headline(event)}*", event.get("summary") or ""]
    lines += [f"• {k}: {v}" for k, v in _facts(event)]
    return {"text": "\n".join(lines)}


def teams_body(event: dict[str, Any]) -> dict[str, Any]:
    """An Adaptive Card, which both Teams Workflows webhooks and the older incoming webhooks accept."""
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {"type": "TextBlock", "text": _headline(event), "weight": "Bolder", "size": "Medium", "wrap": True,
             "color": "Attention" if event.get("verdict") == "FAIL" else "Default"},
            {"type": "TextBlock", "text": event.get("summary") or "", "wrap": True},
            {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in _facts(event)]},
        ],
    }
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def _cef_header(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def cef_line(event: dict[str, Any]) -> str:
    """ArcSight CEF, which Microsoft Sentinel, Splunk, QRadar and most SIEMs read."""
    severity = 3 if event.get("verdict") == "TEST" else 8
    ext = {
        "rt": int(time.time() * 1000),
        "act": event.get("verdict"),
        "outcome": event.get("reason_code"),
        "msg": event.get("summary"),
        "externalId": event.get("result_id") or event.get("id"),
        "cs1Label": "checkId", "cs1": event.get("check_id"),
        "cs2Label": "workspace", "cs2": event.get("workspace"),
        "cs3Label": "evidenceHash", "cs3": event.get("evidence_hash"),
    }
    extension = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v not in (None, ""))
    header = "|".join(_cef_header(x) for x in ("ThreatSight", "ThreatSight", VERSION, event.get("check_id") or event.get("type"), event.get("title"), severity))
    return f"CEF:0|{header}|{extension}"


def syslog_message(event: dict[str, Any]) -> bytes:
    """RFC 5424 framing; facility security/authorization (4), severity warning (4) or notice (5)."""
    pri = 4 * 8 + (5 if event.get("verdict") == "TEST" else 4)
    host = socket.gethostname()[:255] or "-"
    return f"<{pri}>1 {_now()} {host} threatsight - {event.get('type', '-')} - {cef_line(event)}".encode()


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# Delivery ------------------------------------------------------------------------------------

def deliver(dest: Target, event: dict[str, Any]) -> None:
    """Send one event to one destination. Raises ConnectionError on failure."""
    if dest.kind == "syslog":
        data = syslog_message(event)
        try:
            if dest.protocol == "tcp":
                with socket.create_connection((dest.host, dest.port), timeout=TIMEOUT) as sock:
                    sock.sendall(f"{len(data)} ".encode() + data)  # RFC 6587 octet counting
            else:
                family = socket.AF_INET6 if ":" in (dest.host or "") else socket.AF_INET
                with socket.socket(family, socket.SOCK_DGRAM) as sock:
                    sock.sendto(data[:8192], (dest.host, dest.port))
        except OSError as exc:
            raise ConnectionError(f"syslog {dest.host}:{dest.port}: {exc}") from exc
        return
    payload = {"slack": slack_body, "teams": teams_body}.get(dest.kind, lambda e: e)(event)
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "ThreatSight-Alerts/1.0"}
    if dest.kind == "webhook":
        headers["X-ThreatSight-Event"] = str(event.get("type"))
        if dest.secret:
            headers["X-ThreatSight-Signature"] = sign(dest.secret, body)
    try:
        with open_unredirected(dest.url or "", data=body, headers=headers, method="POST", production=get_settings().is_production) as resp:
            resp.read(1024)
    except urllib.error.HTTPError as exc:
        raise ConnectionError(f"HTTP {exc.code} from {mask_url(dest.url or '')}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise ConnectionError(f"{mask_url(dest.url or '')} unreachable: {getattr(exc, 'reason', exc)}") from exc


def attempt(dest: Target, event: dict[str, Any], tries: int = TRIES) -> dict[str, Any]:
    error = None
    for i in range(tries):
        try:
            deliver(dest, event)
            error = None
            break
        except ConnectionError as exc:
            error = str(exc)[:300]
            if i + 1 < tries:
                time.sleep(RETRY_WAIT * (2 ** i))
    row = {"destination": dest.label, "kind": dest.kind, "event": event.get("type"),
           "subject": str(event.get("result_id") or event.get("id")), "ok": error is None, "error": error}
    logger.info("alert_delivery", **{("event_type" if k == "event" else k): v for k, v in row.items()})
    _record(dest, row)
    return row


def _record(dest: Target, row: dict[str, Any]) -> None:
    try:
        with SessionLocal() as db:
            db.add(AlertDelivery(
                tenant_id=dest.tenant_id, workspace_id=dest.workspace_id, destination_id=dest.id,
                destination_label=dest.label, kind=dest.kind, event_type=str(row["event"])[:64],
                subject=str(row["subject"])[:200], ok=row["ok"], error=row["error"],
            ))
            db.commit()
    except Exception:  # noqa: BLE001 - recording a delivery must never raise on the sender thread
        logger.warning("alert_delivery_not_recorded")


_threads: list[threading.Thread] = []


def _send_all(targets: list[Target], events: list[dict[str, Any]]) -> None:
    for event in events:
        for dest in targets:
            attempt(dest, event)


def emit(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, events: list[dict[str, Any]]) -> None:
    """Send events to every enabled destination of a workspace once the open transaction commits."""
    if not events:
        return
    targets = [
        Target.of(row)
        for row in db.scalars(
            select(AlertDestination).where(
                AlertDestination.tenant_id == tenant_id, AlertDestination.workspace_id == workspace_id, AlertDestination.enabled.is_(True)
            )
        )
    ]
    if not targets:
        return

    def start(_session: Session) -> None:
        thread = threading.Thread(target=_send_all, args=(targets, events), name="alerts", daemon=True)
        _threads[:] = [t for t in _threads if t.is_alive()]
        _threads.append(thread)
        thread.start()

    sa_event.listen(db, "after_commit", start, once=True)


def wait(timeout: float = 30.0) -> None:
    """For tests: block until in-flight deliveries finish."""
    end = time.monotonic() + timeout
    for thread in list(_threads):
        thread.join(max(0.0, end - time.monotonic()))


def notify_result(db: Session, result: Any) -> None:
    """Called when a readiness result is published. Alerts only when the check's fail condition was met."""
    if result.outcome not in ALERT_OUTCOMES:
        return
    from threatsight_api.persistence.models import Workspace
    from threatsight_api.readiness.checks import get_check

    workspace = db.get(Workspace, result.workspace_id)
    emit(db, result.tenant_id, result.workspace_id, [result_event(result, get_check(result.check_id), workspace.key if workspace else None)])
