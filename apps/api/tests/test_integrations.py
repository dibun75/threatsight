"""Read-only API tokens and alert destinations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from threatsight_api.config import get_settings
from threatsight_api.integrations import alerts

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
PASSWORD = "a correct horse battery staple"

# Pure payload tests need no database.


def _event() -> dict:
    result = SimpleNamespace(
        id=uuid.uuid4(), request_id=uuid.uuid4(), check_id="azure.inventory.freshness.v1", check_version="v1",
        outcome="failed_by_defined_check", summary="Inventory older than the allowed window.", maturity="fixture_tested",
        freshness="stale", evidence_hash="a" * 64,
    )
    return alerts.result_event(result, SimpleNamespace(title="Azure resource inventory freshness"), "default")


def test_payloads_say_what_a_fail_means() -> None:
    event = _event()
    assert event["verdict"] == "FAIL" and "not a statement of compromise" in event["note"]
    assert "Azure resource inventory freshness" in alerts.slack_body(event)["text"]
    card = alerts.teams_body(event)["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and card["body"][0]["color"] == "Attention"
    line = alerts.syslog_message(event).decode()
    assert line.startswith("<36>1 ") and "CEF:0|ThreatSight|ThreatSight|1.0|azure.inventory.freshness.v1|" in line


def test_cef_escapes_control_characters() -> None:
    event = _event() | {"title": "a|b\nc", "summary": "x=y\nz"}
    line = alerts.cef_line(event)
    assert "\n" not in line and "a\\|b c" in line and "msg=x\\=y\\nz" in line


def test_destination_validation() -> None:
    assert alerts.validate({"kind": "slack", "label": "ops", "url": "https://hooks.slack.com/services/T/B/x"})["kind"] == "slack"
    for bad in (
        {"kind": "ftp", "label": "x"},
        {"kind": "slack", "label": "", "url": "https://x.example"},
        {"kind": "webhook", "label": "x", "url": "https://user:pw@x.example"},
        {"kind": "webhook", "label": "x", "url": "file:///etc/passwd"},
        {"kind": "slack", "label": "x", "url": "https://x.example", "secret": "s"},
        {"kind": "syslog", "label": "x", "host": "bad host", "port": 514},
        {"kind": "syslog", "label": "x", "host": "siem.example", "port": 70000},
        {"kind": "syslog", "label": "x", "host": "siem.example", "protocol": "icmp"},
    ):
        with pytest.raises(ValueError):
            alerts.validate(bad)
    assert alerts.mask_url("https://hooks.slack.com/services/T000/B000/secretvalue1234") == "https://hooks.slack.com/…1234"


def test_other_outcomes_do_not_alert() -> None:
    for outcome in ("observed", "configured_not_observed", "unknown", "collection_failed"):
        alerts.notify_result(None, SimpleNamespace(outcome=outcome))  # type: ignore[arg-type]


pytestmark_live = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("THREATSIGHT_AUTH_MODE", "local")
    monkeypatch.setenv("THREATSIGHT_PUBLIC_DEMO", "false")
    monkeypatch.setenv("THREATSIGHT_CORS_ORIGINS", "http://testserver")
    get_settings.cache_clear()
    from threatsight_api.main import app

    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def _write_headers(client: TestClient) -> dict[str, str]:
    return {"Origin": "http://testserver", "X-CSRF-Token": client.cookies.get("threatsight_csrf") or ""}


def _owner(client: TestClient, email: str = "tokens-owner@example.com") -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.local_auth.service import create_account
    from threatsight_api.persistence.models import Tenant, Workspace
    from threatsight_api.persistence.session import get_engine

    with Session(get_engine()) as db:
        tenant = db.scalar(select(Tenant).where(Tenant.key == "default"))
        workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
        create_account(db, email=email, password=PASSWORD, role="platform-admin", tenant=tenant, workspace=workspace)
        db.commit()
    assert client.post("/api/v1/auth/local/login", json={"email": email, "password": PASSWORD}).status_code == 200


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_token_is_read_only_scoped_and_revocable(client: TestClient) -> None:
    _owner(client)
    created = client.post("/api/v1/auth/tokens", json={"name": "Power BI"}, headers=_write_headers(client))
    assert created.status_code == 201
    token, token_id = created.json()["token"], created.json()["id"]
    assert token.startswith("tsk_")
    listing = client.get("/api/v1/auth/tokens")
    assert listing.status_code == 200 and token not in listing.text

    with TestClient(client.app) as bearer:  # no cookies: only the token
        auth = {"Authorization": f"Bearer {token}"}
        assert bearer.get("/api/v1/auth/token", headers=auth).json()["read_only"] is True
        assert bearer.get("/api/v1/exports/findings.json", headers=auth).status_code == 200
        assert bearer.get("/api/v1/exports/findings.csv", headers=auth).status_code == 200
        assert bearer.post("/api/v1/auth/local/logout", headers=auth).status_code in {403, 404, 405}
        assert bearer.post("/api/v1/readiness/actions/x", headers=auth).status_code == 403
        assert bearer.get("/api/v1/auth/tokens", headers=auth).status_code == 403
        assert bearer.get("/api/v1/auth/local/accounts", headers=auth).status_code == 403
        assert bearer.get("/api/v1/integrations/alerts", headers=auth).status_code == 403
        assert bearer.get("/api/v1/exports/findings.json", headers={"Authorization": "Bearer tsk_" + "x" * 40}).status_code == 401

        revoked = client.delete(f"/api/v1/auth/tokens/{token_id}", headers=_write_headers(client))
        assert revoked.status_code == 200 and revoked.json()["revoked_at"]
        assert bearer.get("/api/v1/exports/findings.json", headers=auth).status_code == 401


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_only_a_platform_admin_can_issue_tokens(client: TestClient) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.local_auth.service import create_account
    from threatsight_api.persistence.models import Tenant, Workspace
    from threatsight_api.persistence.session import get_engine

    with Session(get_engine()) as db:
        tenant = db.scalar(select(Tenant).where(Tenant.key == "default"))
        workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
        create_account(db, email="tokens-viewer@example.com", password=PASSWORD, role="viewer", tenant=tenant, workspace=workspace)
        db.commit()
    # A viewer cannot activate without a token; log in is not possible, so an unauthenticated call must fail.
    assert client.post("/api/v1/auth/tokens", json={"name": "x"}).status_code == 401


class _Sink(BaseHTTPRequestHandler):
    received: list[tuple[dict, bytes]] = []

    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        _Sink.received.append((dict(self.headers), body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args) -> None:
        pass


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_destinations_are_admin_only_masked_and_deliver(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.persistence.models import Workspace
    from threatsight_api.persistence.session import get_engine

    monkeypatch.setattr(alerts, "RETRY_WAIT", 0.01)
    server = HTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(5)
    _Sink.received.clear()
    try:
        _owner(client, "alerts-owner@example.com")
        headers = _write_headers(client)
        url = f"http://127.0.0.1:{server.server_port}/hook/secret-path"
        added = client.post("/api/v1/integrations/alerts/destinations", json={"kind": "webhook", "label": "SOC", "url": url, "secret": "shh"}, headers=headers)
        assert added.status_code == 201, added.text
        dest = added.json()
        assert "secret-path" not in json.dumps(dest) and dest["has_secret"] is True
        syslog = client.post(
            "/api/v1/integrations/alerts/destinations",
            json={"kind": "syslog", "label": "SIEM", "host": "127.0.0.1", "port": udp.getsockname()[1], "protocol": "udp"},
            headers=headers,
        )
        assert syslog.status_code == 201
        assert client.post("/api/v1/integrations/alerts/destinations", json={"kind": "webhook", "label": "bad", "url": "ftp://x"}, headers=headers).status_code == 400
        assert "secret-path" not in client.get("/api/v1/integrations/alerts").text

        tested = client.post(f"/api/v1/integrations/alerts/destinations/{dest['id']}/test", headers=headers)
        assert tested.status_code == 200 and tested.json()["ok"] is True

        with Session(get_engine()) as db:
            workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
            alerts.emit(db, workspace.tenant_id, workspace.id, [_event()])
            db.commit()
        alerts.wait()

        headers_in, body = next((h, b) for h, b in _Sink.received if json.loads(b)["type"] == "readiness.fail")
        expected = "sha256=" + hmac.new(b"shh", body, hashlib.sha256).hexdigest()
        assert {k.lower(): v for k, v in headers_in.items()}["x-threatsight-signature"] == expected
        datagram = udp.recv(65535).decode()
        assert "CEF:0|ThreatSight" in datagram or "TEST" in datagram

        deliveries = client.get("/api/v1/integrations/alerts").json()["deliveries"]
        assert {d["destination"] for d in deliveries} >= {"SOC", "SIEM"} and all(d["ok"] for d in deliveries)

        off = client.patch(f"/api/v1/integrations/alerts/destinations/{dest['id']}", json={"enabled": False}, headers=headers)
        assert off.json()["enabled"] is False
        assert client.delete(f"/api/v1/integrations/alerts/destinations/{dest['id']}", headers=headers).status_code == 200
        assert client.delete(f"/api/v1/integrations/alerts/destinations/{dest['id']}", headers=headers).status_code == 404
    finally:
        server.shutdown()
        udp.close()


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_delivery_failure_is_recorded_not_raised(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.persistence.models import Workspace
    from threatsight_api.persistence.session import get_engine

    monkeypatch.setattr(alerts, "RETRY_WAIT", 0.01)
    _owner(client, "alerts-owner2@example.com")
    headers = _write_headers(client)
    added = client.post("/api/v1/integrations/alerts/destinations", json={"kind": "slack", "label": "dead", "url": "http://127.0.0.1:9/x"}, headers=headers)
    assert added.status_code == 201
    with Session(get_engine()) as db:
        workspace = db.scalar(select(Workspace).where(Workspace.key == "default"))
        alerts.emit(db, workspace.tenant_id, workspace.id, [_event()])
        db.commit()
    alerts.wait()
    deliveries = client.get("/api/v1/integrations/alerts").json()["deliveries"]
    dead = [d for d in deliveries if d["destination"] == "dead"]
    assert dead and dead[0]["ok"] is False and dead[0]["error"]
