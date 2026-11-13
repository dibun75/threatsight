"""Alerts out of ThreatSight: a webhook, Slack, Microsoft Teams or a SIEM (syslog with CEF) on every FAIL.

The owner adds destinations on the Integrations page (the web middleware lets only the owner see or
change them). They are kept in ``integrations.json`` in the runs volume (mode 0600) because webhook
URLs carry their own secret; browsers only ever get a masked URL back.

Delivery runs on a background thread so a slow receiver never holds up a run. Each delivery is
tried up to three times and the last results are kept for the page to show.

Every event says ``"synthetic": true``: the demo world is fictional, and receivers should be able to
filter it out.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEST_ID = re.compile(r"^hk-[0-9a-f]{8}$")
KINDS = ("webhook", "slack", "teams", "syslog")
MAX_DESTINATIONS = 20
TRIES = 3
TIMEOUT = 10.0
HISTORY = 50
VERSION = "1.0"


@dataclass
class Destination:
    id: str
    kind: str
    label: str
    url: str | None = None
    secret: str | None = None
    host: str | None = None
    port: int | None = None
    protocol: str = "udp"
    enabled: bool = True
    created: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def public(self) -> dict[str, Any]:
        target = f"{self.protocol}://{self.host}:{self.port}" if self.kind == "syslog" else mask_url(self.url or "")
        return {"id": self.id, "kind": self.kind, "label": self.label, "target": target, "has_secret": bool(self.secret),
                "enabled": self.enabled, "created": self.created}


def mask_url(url: str) -> str:
    """Show where a webhook goes without its secret path: https://hooks.slack.com/…a1b2"""
    u = urlparse(url)
    tail = url[-4:] if len(url) > 12 else ""
    return f"{u.scheme}://{u.hostname}{':' + str(u.port) if u.port else ''}/…{tail}"


def validate(body: dict[str, Any]) -> Destination:
    kind = str(body.get("kind") or "")
    label = str(body.get("label") or "").strip()
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {list(KINDS)}")
    if not label or len(label) > 80:
        raise ValueError("give the destination a name of at most 80 characters")
    dest = Destination(f"hk-{uuid.uuid4().hex[:8]}", kind, label)
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
        dest.host, dest.port, dest.protocol = host.strip("[]"), port, protocol
    else:
        url = str(body.get("url") or "").strip()
        u = urlparse(url)
        if u.scheme not in {"http", "https"} or not u.hostname or len(url) > 1000 or u.username or u.password:
            raise ValueError("URL must be an http(s) address without a user or password in it")
        dest.url = url
        secret = str(body.get("secret") or "").strip() or None
        if secret is not None and (kind != "webhook" or len(secret) > 200):
            raise ValueError("a signing secret is only for plain webhooks, at most 200 characters")
        dest.secret = secret
    return dest


# Event payloads ------------------------------------------------------------------------------

def run_events(record: dict[str, Any], control: dict[str, Any], public_url: str | None) -> list[dict[str, Any]]:
    """One event when a run's final verdict is FAIL, describing the run that did harm."""
    if record.get("verdict") != "FAIL":
        return []
    approval = next((a for a in record.get("approvals", []) if a["verdict"]["verdict"] == "FAIL"), None)
    last = record["runs"][-1]
    verdict = approval["verdict"] if approval else last["verdict"]
    return [{
        "source": "threatsight",
        "version": VERSION,
        "type": "agent_attack.fail",
        "id": str(uuid.uuid4()),
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "synthetic": bool(record.get("synthetic")),
        "organisation": record.get("organisation"),
        "run_id": record["id"],
        "scenario": record["scenario"],
        "title": record["title"],
        "agent": record["agent"],
        "control": record["control"],
        "control_title": control.get("title"),
        "model": last["model"],
        "policy": last["policy"],
        "verdict": "FAIL",
        "reason_code": verdict["reason_code"],
        "summary": verdict["summary"],
        "approver": approval["approver"] if approval else None,
        "owasp_llm": list(control.get("tags", [])),
        "owasp_agentic": list(control.get("agentic", [])),
        "mitre_atlas": list(control.get("atlas", [])),
        "evidence": {"head": record["evidence"]["head"], "valid": record["evidence"]["valid"], "records": record["evidence"]["records"]},
        "link": f"{public_url.rstrip('/')}/agents/report/{record['id']}" if public_url else None,
    }]


def comparison_event(job: dict[str, Any], public_url: str | None) -> list[dict[str, Any]]:
    """One event when a finished comparison found harm: per model, attacks that did harm with and without the policy."""
    summary = job.get("summary") or []
    if not any(s["harm_before"] or s["harm_after"] for s in summary):
        return []
    worst = max(summary, key=lambda s: (s["harm_after"], s["harm_before"]))
    return [{
        "source": "threatsight",
        "version": VERSION,
        "type": "comparison.fail",
        "id": str(uuid.uuid4()),
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "synthetic": True,
        "comparison_id": job["id"],
        "policy": job.get("policy"),
        "verdict": "FAIL",
        "reason_code": "MODEL_DID_HARM",
        "title": "Model comparison found attacks that did harm",
        "summary": f"{worst['label']}: {worst['harm_before']} of {worst['scenarios']} attacks did harm without the policy, "
                   f"{worst['harm_after']} with it.",
        "models": [{k: s[k] for k in ("model", "label", "harm_before", "harm_after", "work_passed", "work_total", "scenarios")} for s in summary],
        "evidence": job.get("evidence"),
        "link": f"{public_url.rstrip('/')}/compare?id={job['id']}" if public_url else None,
    }]


def ping_event(public_url: str | None) -> dict[str, Any]:
    return {
        "source": "threatsight", "version": VERSION, "type": "test", "id": str(uuid.uuid4()),
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "synthetic": True, "verdict": "TEST",
        "reason_code": "TEST", "title": "ThreatSight test alert", "control": "TEST",
        "summary": "This is a test from the ThreatSight Integrations page. Real alerts arrive when an attack does harm.",
        "link": public_url,
    }


def _facts(event: dict[str, Any]) -> list[tuple[str, str]]:
    rows = [("Agent", event.get("agent")), ("Control", event.get("control")), ("Model", event.get("model")),
            ("Policy", event.get("policy")), ("Reason", event.get("reason_code")),
            ("MITRE ATLAS", ", ".join(x.split(" ")[0] for x in event.get("mitre_atlas") or [])),
            ("OWASP", ", ".join(x.split(" ")[0] for x in (event.get("owasp_llm") or []) + (event.get("owasp_agentic") or [])))]
    for m in event.get("models") or []:
        rows.append((m["label"], f"harm without policy {m['harm_before']}/{m['scenarios']}, with policy {m['harm_after']}/{m['scenarios']}"))
    return [(k, str(v)) for k, v in rows if v]


def _headline(event: dict[str, Any]) -> str:
    tag = "[synthetic] " if event.get("synthetic") else ""
    return f"{tag}ThreatSight {event.get('verdict')}: {event.get('title')}"


def slack_body(event: dict[str, Any]) -> dict[str, Any]:
    lines = [f"*{_headline(event)}*", event.get("summary") or ""]
    lines += [f"• {k}: {v}" for k, v in _facts(event)]
    if event.get("link"):
        lines.append(f"<{event['link']}|Open in ThreatSight>")
    return {"text": "\n".join(lines)}


def teams_body(event: dict[str, Any]) -> dict[str, Any]:
    """An Adaptive Card, which both Teams Workflows webhooks and the older incoming webhooks accept."""
    card: dict[str, Any] = {
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
    if event.get("link"):
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in ThreatSight", "url": event["link"]}]
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
        "externalId": event.get("run_id") or event.get("comparison_id") or event.get("id"),
        "suser": event.get("agent"),
        "request": event.get("link"),
        "cs1Label": "model", "cs1": event.get("model"),
        "cs2Label": "policy", "cs2": event.get("policy"),
        "cs3Label": "mitreAtlas", "cs3": ", ".join(x.split(" ")[0] for x in event.get("mitre_atlas") or []),
        "cs4Label": "owasp", "cs4": ", ".join(x.split(" ")[0] for x in (event.get("owasp_llm") or []) + (event.get("owasp_agentic") or [])),
        "cs5Label": "evidenceHead", "cs5": (event.get("evidence") or {}).get("head"),
        "cs6Label": "synthetic", "cs6": str(bool(event.get("synthetic"))).lower(),
    }
    extension = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v not in (None, ""))
    header = "|".join(_cef_header(x) for x in ("ThreatSight", "ThreatSight", VERSION, event.get("control") or event.get("type"), event.get("title"), severity))
    return f"CEF:0|{header}|{extension}"


def syslog_message(event: dict[str, Any]) -> bytes:
    """RFC 5424 framing; facility security/authorization (4), severity warning (4) or notice (5)."""
    pri = 4 * 8 + (5 if event.get("verdict") == "TEST" else 4)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    host = socket.gethostname()[:255] or "-"
    return f"<{pri}>1 {stamp} {host} threatsight - {event.get('type', '-')} - {cef_line(event)}".encode()


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# Delivery ------------------------------------------------------------------------------------

def deliver(dest: Destination, event: dict[str, Any]) -> None:
    """Send one event to one destination. Raises ConnectionError on failure."""
    if dest.kind == "syslog":
        data = syslog_message(event)
        try:
            if dest.protocol == "tcp":
                with socket.create_connection((dest.host, dest.port), timeout=TIMEOUT) as s:
                    s.sendall(f"{len(data)} ".encode() + data)  # RFC 6587 octet counting
            else:
                with socket.socket(socket.AF_INET6 if ":" in (dest.host or "") else socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(data[:8192], (dest.host, dest.port))
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
    req = urllib.request.Request(dest.url or "", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            resp.read(1024)
    except urllib.error.HTTPError as exc:
        raise ConnectionError(f"HTTP {exc.code} from {mask_url(dest.url or '')}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ConnectionError(f"{mask_url(dest.url or '')} unreachable: {getattr(exc, 'reason', exc)}") from exc


class Integrations:
    def __init__(self, data_dir: Path, public_url: str | None = None, retry_wait: float = 2.0) -> None:
        self.path = data_dir / "integrations.json"
        self.public_url = public_url
        self.retry_wait = retry_wait
        self._lock = threading.Lock()
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)
        self._worker: threading.Thread | None = None
        self.history: deque[dict[str, Any]] = deque(maxlen=HISTORY)

    # Storage --------------------------------------------------------------------------------

    def destinations(self) -> list[Destination]:
        if not self.path.is_file():
            return []
        try:
            rows = json.loads(self.path.read_text())
            return [Destination(**r) for r in rows if isinstance(r, dict) and DEST_ID.match(str(r.get("id", "")))]
        except (OSError, ValueError, TypeError):
            return []

    def _save(self, items: list[Destination]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([asdict(d) for d in items], indent=2))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def add(self, body: dict[str, Any]) -> Destination:
        dest = validate(body)
        with self._lock:
            items = self.destinations()
            if len(items) >= MAX_DESTINATIONS:
                raise ValueError(f"at most {MAX_DESTINATIONS} destinations; remove one first")
            self._save([*items, dest])
        return dest

    def remove(self, dest_id: str) -> bool:
        with self._lock:
            items = self.destinations()
            kept = [d for d in items if d.id != dest_id]
            if len(kept) == len(items):
                return False
            self._save(kept)
        return True

    def set_enabled(self, dest_id: str, enabled: bool) -> Destination | None:
        with self._lock:
            items = self.destinations()
            found = next((d for d in items if d.id == dest_id), None)
            if found:
                found.enabled = enabled
                self._save(items)
        return found

    def view(self) -> dict[str, Any]:
        return {"destinations": [d.public() for d in self.destinations()], "deliveries": list(reversed(self.history))}

    # Sending --------------------------------------------------------------------------------

    def test(self, dest_id: str) -> dict[str, Any] | None:
        dest = next((d for d in self.destinations() if d.id == dest_id), None)
        if dest is None:
            return None
        return self._attempt(dest, ping_event(self.public_url), tries=1)

    def emit(self, events: list[dict[str, Any]]) -> None:
        """Queue events for every enabled destination. Never blocks the caller."""
        if not events or not any(d.enabled for d in self.destinations()):
            return
        for event in events:
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                self.history.append({"time": event.get("time"), "event": event.get("type"), "destination": None, "ok": False,
                                     "error": "alert queue full; event dropped"})
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._drain, name="alerts", daemon=True)
                self._worker.start()

    def _drain(self) -> None:
        while True:
            try:
                event = self._queue.get(timeout=1)
            except queue.Empty:
                return
            try:
                for dest in self.destinations():
                    if dest.enabled:
                        self._attempt(dest, event, TRIES)
            finally:
                self._queue.task_done()

    def wait(self, timeout: float = 30.0) -> None:
        """For tests: block until the queue is empty."""
        end = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < end:
            time.sleep(0.05)

    def _attempt(self, dest: Destination, event: dict[str, Any], tries: int) -> dict[str, Any]:
        error = None
        for i in range(tries):
            try:
                deliver(dest, event)
                error = None
                break
            except ConnectionError as exc:
                error = str(exc)[:300]
                if i + 1 < tries:
                    time.sleep(self.retry_wait * (2 ** i))
        row = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event.get("type"), "subject": event.get("run_id") or event.get("comparison_id"),
               "destination": dest.label, "kind": dest.kind, "ok": error is None, "error": error}
        self.history.append(row)
        print(json.dumps({"event": "alert_delivery", **row}), flush=True)
        return row
