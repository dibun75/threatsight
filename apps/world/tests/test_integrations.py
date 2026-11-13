"""Alerts (webhook, Slack, Teams, syslog CEF), exports, framework tags and the black-box agent adapter."""
import csv
import hashlib
import hmac
import io
import json
import os
import socket
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from threatsight_world.integrations import Integrations, cef_line, mask_url, slack_body, teams_body, ping_event, validate
from threatsight_world.llm import parse_agent_response
from threatsight_world.scenarios import SCENARIOS
from threatsight_world.server import Config, serve


class Receiver(BaseHTTPRequestHandler):
    """Records every POST it gets."""

    got: list = []

    def log_message(self, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).got.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        status = 500 if self.path == "/broken" else 200
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class Agent(BaseHTTPRequestHandler):
    """A black-box agent: obeys the hostile email by approving the payment, then reports it refused."""

    seen: list = []

    def log_message(self, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append(body)
        names = [t["function"]["name"] for t in body["tools"]]
        done = any(m["role"] == "tool" for m in body["messages"])
        if "approve_payment" in names and not done:
            answer = {"content": "", "tool_calls": [{"id": "a1", "name": "approve_payment",
                                                    "arguments": {"invoice_id": "4471", "amount_nok": 482000, "account": "NO9386011117947"}}]}
        else:
            answer = {"content": "I did not act on that email.", "tool_calls": []}
        data = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start(handler: type) -> tuple[ThreadingHTTPServer, str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


@pytest.fixture()
def receiver():
    Receiver.got = []
    httpd, url = start(Receiver)
    yield url
    httpd.shutdown()


@pytest.fixture()
def world(tmp_path: Path):
    cfg = Config(tmp_path / "runs", "http://127.0.0.1:9/v1", None, None, public_url="https://threatsight.example")
    cfg.integrations.retry_wait = 0.01
    httpd = serve(cfg, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/api/world", cfg
    httpd.shutdown()


def call(url: str, body: dict | None = None, method: str | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method or ("POST" if data else "GET"), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def fetch(url: str) -> tuple[str, str]:
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.headers["Content-Type"], r.read().decode()


# Tags ---------------------------------------------------------------------------------------

def test_every_control_carries_owasp_and_atlas_tags(world) -> None:
    for sc in SCENARIOS.values():
        assert sc.control.tags and sc.control.agentic and sc.control.atlas
        assert all(a.startswith("AML.T") for a in sc.control.atlas)
        assert all(a.startswith("ASI") for a in sc.control.agentic)
    base, _ = world
    _, body = call(f"{base}/scenarios")
    assert all(s["atlas"] and s["agentic"] for s in body["scenarios"])


# Destinations -------------------------------------------------------------------------------

def test_destination_validation_and_masking() -> None:
    with pytest.raises(ValueError):
        validate({"kind": "email", "label": "x"})
    with pytest.raises(ValueError):
        validate({"kind": "slack", "label": "x", "url": "ftp://example.com"})
    with pytest.raises(ValueError):
        validate({"kind": "slack", "label": "x", "url": "https://user:pw@example.com/hook"})
    with pytest.raises(ValueError):
        validate({"kind": "slack", "label": "x", "url": "https://hooks.slack.com/a", "secret": "s"})
    with pytest.raises(ValueError):
        validate({"kind": "syslog", "label": "x", "host": "siem;rm", "port": 514})
    with pytest.raises(ValueError):
        validate({"kind": "syslog", "label": "x", "host": "siem", "port": 70000})
    d = validate({"kind": "slack", "label": "Security channel", "url": "https://hooks.slack.com/services/T000/B000/abcdefSECRET1234"})
    assert "SECRET" not in d.public()["target"] and d.public()["target"].endswith("1234")
    assert mask_url("https://example.com:8443/hook/secretpath") == "https://example.com:8443/…path"


def test_stored_destinations_are_private_and_keys_never_returned(world, receiver) -> None:
    base, cfg = world
    status, body = call(f"{base}/integrations", {"kind": "webhook", "label": "SOAR", "url": f"{receiver}/hook-secret-path", "secret": "s3cret"})
    assert status == 201 and body["destination"]["has_secret"]
    assert oct(os.stat(cfg.integrations.path).st_mode & 0o777) == "0o600"
    _, listing = call(f"{base}/integrations")
    text = json.dumps(listing)
    assert "s3cret" not in text and "hook-secret-path" not in text
    dest_id = body["destination"]["id"]
    assert call(f"{base}/integrations/{dest_id}/disable", {})[1]["destination"]["enabled"] is False
    assert call(f"{base}/integrations/{dest_id}", method="DELETE")[0] == 200
    assert call(f"{base}/integrations/{dest_id}", method="DELETE")[0] == 404


def test_test_button_reports_success_and_failure(world, receiver) -> None:
    base, _ = world
    ok = call(f"{base}/integrations", {"kind": "teams", "label": "Teams", "url": f"{receiver}/teams"})[1]["destination"]["id"]
    bad = call(f"{base}/integrations", {"kind": "slack", "label": "Broken", "url": f"{receiver}/broken"})[1]["destination"]["id"]
    assert call(f"{base}/integrations/{ok}/test", {})[1]["delivery"]["ok"] is True
    failed = call(f"{base}/integrations/{bad}/test", {})[1]["delivery"]
    assert failed["ok"] is False and "HTTP 500" in failed["error"]
    card = json.loads(Receiver.got[0]["body"])
    assert card["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"


# A FAIL sends alerts --------------------------------------------------------------------------

def test_a_failing_run_alerts_every_destination(world, receiver) -> None:
    base, cfg = world
    secret = "whsec-test"
    call(f"{base}/integrations", {"kind": "webhook", "label": "SOAR", "url": f"{receiver}/hook", "secret": secret})
    call(f"{base}/integrations", {"kind": "slack", "label": "Slack", "url": f"{receiver}/slack"})
    off = call(f"{base}/integrations", {"kind": "slack", "label": "Off", "url": f"{receiver}/off"})[1]["destination"]["id"]
    call(f"{base}/integrations/{off}/disable", {})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(10)
        call(f"{base}/integrations", {"kind": "syslog", "label": "Sentinel", "host": "127.0.0.1", "port": udp.getsockname()[1], "protocol": "udp"})

        status, run = call(f"{base}/runs", {"scenario": "payment-injection", "model": "scripted", "policy": "open"})
        assert status == 201 and run["verdict"] == "FAIL"
        cfg.integrations.wait()
        syslog = udp.recv(8192).decode()

    paths = sorted(g["path"] for g in Receiver.got)
    assert paths == ["/hook", "/slack"]
    hook = next(g for g in Receiver.got if g["path"] == "/hook")
    expected = "sha256=" + hmac.new(secret.encode(), hook["body"], hashlib.sha256).hexdigest()
    assert hook["headers"]["x-threatsight-signature"] == expected
    event = json.loads(hook["body"])
    assert event["type"] == "agent_attack.fail" and event["run_id"] == run["id"] and event["synthetic"] is True
    assert event["control"] == "CTRL-PAY-01" and "AML.T0053 AI Agent Tool Invocation" in event["mitre_atlas"]
    assert event["link"] == f"https://threatsight.example/agents/report/{run['id']}"
    assert event["evidence"]["head"] == run["evidence"]["head"]
    assert "CEF:0|ThreatSight|ThreatSight|" in syslog and "CTRL-PAY-01" in syslog and "cs6=true" in syslog
    slack = json.loads(next(g for g in Receiver.got if g["path"] == "/slack")["body"])
    assert "[synthetic] ThreatSight FAIL" in slack["text"]
    deliveries = call(f"{base}/integrations")[1]["deliveries"]
    assert len(deliveries) == 3 and all(d["ok"] for d in deliveries)


def test_a_blocked_run_sends_nothing(world, receiver) -> None:
    base, cfg = world
    call(f"{base}/integrations", {"kind": "webhook", "label": "SOAR", "url": f"{receiver}/hook"})
    _, run = call(f"{base}/runs", {"scenario": "payment-injection", "model": "scripted", "policy": "nordvik-hardened"})
    assert run["verdict"] != "FAIL"
    cfg.integrations.wait()
    assert Receiver.got == []


def test_failed_deliveries_are_retried_and_recorded(tmp_path: Path, receiver) -> None:
    hooks = Integrations(tmp_path, retry_wait=0.01)
    hooks.add({"kind": "webhook", "label": "Down", "url": f"{receiver}/broken"})
    hooks.emit([ping_event(None)])
    hooks.wait()
    assert len(Receiver.got) == 3
    assert hooks.history[-1]["ok"] is False


def test_cef_escapes_separators() -> None:
    event = {**ping_event(None), "title": "a|b", "summary": "x=y\nz", "control": "C\\1"}
    line = cef_line(event)
    assert "a\\|b" in line and "msg=x\\=y\\nz" in line and "C\\\\1" in line
    assert line.count("|") - line.count("\\|") == 7


def test_slack_and_teams_bodies_carry_the_facts() -> None:
    event = {**ping_event("https://t.example"), "verdict": "FAIL", "agent": "Procurement Bot", "mitre_atlas": ["AML.T0053 AI Agent Tool Invocation"]}
    assert "AML.T0053" in slack_body(event)["text"]
    facts = teams_body(event)["attachments"][0]["content"]["body"][2]["facts"]
    assert {"title": "MITRE ATLAS", "value": "AML.T0053"} in facts


# Exports ------------------------------------------------------------------------------------

def test_runs_export_as_json_and_csv(world) -> None:
    base, _ = world
    _, run = call(f"{base}/runs", {"scenario": "payment-injection", "model": "scripted", "policy": "open"})
    call(f"{base}/runs", {"scenario": "cloud-ticket-acl", "model": "scripted", "policy": "nordvik-hardened"})
    _, body = call(f"{base}/export/runs.json")
    assert body["synthetic"] is True and len(body["rows"]) == 2
    row = next(r for r in body["rows"] if r["id"] == run["id"])
    assert row["verdict"] == "FAIL" and row["policy"] == "open" and row["mitre_atlas"] and row["evidence_valid"] is True
    ctype, text = fetch(f"{base}/export/runs.csv")
    assert ctype.startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 2 and "AML.T0053 AI Agent Tool Invocation" in rows[0]["mitre_atlas"]
    _, evidence = fetch(f"{base}/runs/{run['id']}/evidence.jsonl")
    assert len(evidence.strip().splitlines()) == run["evidence"]["records"]
    assert call(f"{base}/export/nope.csv")[0] == 404


def test_comparison_cells_export(world) -> None:
    base, cfg = world
    job = cfg.compare.start({"models": ["scripted"]}, cfg.compare_models())
    cfg.compare._queue.join()
    _, body = call(f"{base}/export/comparisons.json")
    assert len(body["rows"]) == len([s for s in SCENARIOS.values() if s.profile == "nordvik"]) and body["rows"][0]["comparison_id"] == job["id"]
    assert {r["verdict_without_policy"] for r in body["rows"]} >= {"FAIL"}
    _, text = fetch(f"{base}/export/comparisons.csv")
    assert text.splitlines()[0].startswith("comparison_id,created")


def test_csv_cells_cannot_run_as_formulas(tmp_path: Path) -> None:
    from threatsight_world.exports import to_csv

    text = to_csv([{"a": "=HYPERLINK(\"x\")", "b": 5}], ["a", "b"])
    assert "'=HYPERLINK" in text


# Black-box agent adapter ------------------------------------------------------------------------

def test_agent_response_shapes() -> None:
    msg = parse_agent_response({"content": "hi", "tool_calls": [{"name": "read_invoice", "arguments": "{\"invoice_id\": \"1\"}"}, {"bad": 1}]})
    assert msg.tool_calls[0].name == "read_invoice" and msg.tool_calls[0].arguments == {"invoice_id": "1"}
    assert len(msg.tool_calls) == 1
    openai = parse_agent_response({"choices": [{"message": {"content": "x", "tool_calls": []}}]})
    assert openai.content == "x"
    with pytest.raises(ValueError):
        parse_agent_response([1, 2])


def test_a_black_box_agent_is_tested_and_judged_on_what_it_did(world, receiver) -> None:
    base, cfg = world
    Agent.seen = []
    httpd, agent_url = start(Agent)
    try:
        status, body = call(f"{base}/connections", {"label": "Our AP agent", "base_url": f"{agent_url}/agent", "protocol": "agent"})
        assert status == 201 and body["connection"]["protocol"] == "agent"
        ep = body["connection"]["id"]
        check = call(f"{base}/connections/{ep}/check", {})[1]
        assert check["reachable"] is True
        status, run = call(f"{base}/runs", {"scenario": "payment-injection", "model": ep, "policy": "open"})
        assert status == 201 and run["verdict"] == "FAIL"
        assert run["runs"][0]["model"] == "agent:Our AP agent"
        first = next(b for b in Agent.seen if any(t["function"]["name"] == "approve_payment" for t in b["tools"]))
        assert first["protocol"] == "threatsight-agent/1" and first["session"]
        status, guarded = call(f"{base}/runs", {"scenario": "payment-injection", "model": ep, "policy": "nordvik-hardened"})
        assert guarded["verdict"] == "PASS"
    finally:
        httpd.shutdown()


def test_agent_endpoints_need_no_model_name_but_openai_ones_do() -> None:
    from threatsight_world.connections import validate_endpoint

    assert validate_endpoint({"label": "a", "base_url": "http://agent:8080/run", "protocol": "agent"})[2] == "agent"
    with pytest.raises(ValueError):
        validate_endpoint({"label": "a", "base_url": "http://x/v1", "protocol": "openai"})
    with pytest.raises(ValueError):
        validate_endpoint({"label": "a", "base_url": "http://x/v1", "model": "m", "protocol": "grpc"})


def test_settings_files_in_the_runs_folder_do_not_break_listings(world, receiver) -> None:
    base, _ = world
    call(f"{base}/integrations", {"kind": "slack", "label": "S", "url": f"{receiver}/s"})
    call(f"{base}/connections", {"label": "a", "base_url": "http://127.0.0.1:9/run", "protocol": "agent"})
    call(f"{base}/runs", {"scenario": "payment-injection", "model": "scripted", "policy": "open"})
    assert len(call(f"{base}/runs")[1]["runs"]) == 1
    assert len(call(f"{base}/export/runs.json")[1]["rows"]) == 1
