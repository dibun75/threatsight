import ast
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from threatsight_world.server import Config, serve

SRC = Path(__file__).resolve().parents[1] / "src" / "threatsight_world"


@pytest.fixture()
def base(tmp_path: Path):
    httpd = serve(Config(tmp_path / "runs", "http://127.0.0.1:9/v1", None, None), "127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", tmp_path / "runs"
    httpd.shutdown()


def call(url: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_every_response_is_labelled_synthetic(base) -> None:
    url, _ = base
    for path in ("meta", "scenarios", "graph", "graph?policy=nordvik-hardened", "runs"):
        status, body = call(f"{url}/api/world/{path}")
        assert status == 200
        assert body["synthetic"] is True
        assert "fictional" in body["organisation"]
    assert call(f"{url}/api/world/meta")[1]["models"] == ["scripted"]


def test_graph_scores_drop_under_policy(base) -> None:
    url, _ = base
    open_ = {a["id"]: a["score"] for a in call(f"{url}/api/world/graph")[1]["agents"]}
    hard = {a["id"]: a["score"] for a in call(f"{url}/api/world/graph?policy=nordvik-hardened")[1]["agents"]}
    assert all(hard[k] < open_[k] for k in open_)


def test_run_retest_and_verify_round_trip(base) -> None:
    url, runs = base
    status, run = call(f"{url}/api/world/runs", {"scenario": "payment-injection", "policy": "open"})
    assert status == 201 and run["verdict"] == "FAIL" and run["synthetic"] is True
    assert run["evidence"]["valid"] is True

    status, rt = call(f"{url}/api/world/runs", {"scenario": "payment-injection", "mode": "retest"})
    assert status == 201
    assert [r["verdict"]["verdict"] for r in rt["runs"]] == ["FAIL", "PASS"]
    assert all(t["passed"] for t in rt["utility"])

    listed = call(f"{url}/api/world/runs")[1]["runs"]
    assert {r["id"] for r in listed} == {run["id"], rt["id"]}
    assert call(f"{url}/api/world/runs/{rt['id']}")[1]["runs"][1]["policy"] == "nordvik-hardened"
    assert call(f"{url}/api/world/runs/{rt['id']}/verify")[1]["valid"] is True

    # Tamper with one evidence line: verification must fail.
    p = runs / f"{rt['id']}.evidence.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["payload"]["tampered"] = True
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    assert call(f"{url}/api/world/runs/{rt['id']}/verify")[1]["valid"] is False


def test_bad_requests_are_refused(base) -> None:
    url, _ = base
    assert call(f"{url}/api/world/runs", {"scenario": "nope"})[0] == 400
    assert call(f"{url}/api/world/runs", {"scenario": "payment-injection", "policy": "/etc/passwd"})[0] == 400
    # The client cannot choose a live model the operator did not configure.
    assert call(f"{url}/api/world/runs", {"scenario": "payment-injection", "model": "live"})[0] == 400
    assert call(f"{url}/api/world/runs/../../etc/passwd")[0] == 404
    assert call(f"{url}/api/world/graph?policy=x")[0] == 400


def test_world_package_never_touches_the_real_database() -> None:
    """The demo world must stay separate from ThreatSight's real data."""
    banned = {"threatsight_api", "sqlalchemy", "psycopg", "psycopg2", "alembic"}
    for py in SRC.glob("*.py"):
        for node in ast.walk(ast.parse(py.read_text())):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            for n in names:
                assert n.split(".")[0] not in banned, f"{py.name} imports {n}"


def test_recorded_runs_replay_through_the_server(tmp_path: Path) -> None:
    from threatsight_world import cli

    rec = tmp_path / "recordings"
    assert cli.main(["record", "--out", str(rec), "--tries", "2"]) == 0
    header = json.loads((rec / "payment-injection.jsonl").read_text().splitlines()[0])
    assert header["tries"] == 1 and header["max_tries"] == 2 and header["hostile_attempt"] is True

    httpd = serve(Config(tmp_path / "runs", "http://127.0.0.1:9/v1", None, None, rec), "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        assert call(f"{url}/api/world/meta")[1]["models"] == ["scripted", "replay"]
        sc = {s["id"]: s for s in call(f"{url}/api/world/scenarios")[1]["scenarios"]}
        assert sc["cloud-ticket-acl"]["replay"]["tries"] == 1
        status, run = call(f"{url}/api/world/runs", {"scenario": "payment-injection", "mode": "retest", "model": "replay"})
        assert status == 201
        assert [r["verdict"]["verdict"] for r in run["runs"]] == ["FAIL", "PASS"]
        assert run["runs"][0]["model"] == "replay:scripted"
        # Routine tasks were recorded too, so the utility check replays instead of being skipped.
        assert all(t["passed"] is True for t in run["utility"])
    finally:
        httpd.shutdown()


def test_replay_needs_a_recording(base) -> None:
    url, _ = base
    assert call(f"{url}/api/world/runs", {"scenario": "payment-injection", "model": "replay"})[0] == 400


def test_held_payment_needs_a_named_person(base) -> None:
    url, _ = base
    status, run = call(f"{url}/api/world/runs", {"scenario": "payment-injection", "policy": "nordvik-hardened"})
    assert status == 201
    held = run["runs"][0]["tool_calls"][0]
    assert held["held"] is True and held["executed"] is False
    assert run["runs"][0]["verdict"]["reason_code"] == "HELD_FOR_APPROVAL"
    path = f"{url}/api/world/runs/{run['id']}/approvals"

    assert call(path, {"run": 0, "call": 0, "decision": "approve"})[0] == 400  # no approver name
    assert call(path, {"run": 0, "call": 5, "decision": "approve", "approver": "Ingrid"})[0] == 400

    # Approving a payment to an unregistered account is harm, and the record names who approved it.
    status, after = call(path, {"run": 0, "call": 0, "decision": "approve", "approver": "Ingrid Dahl (finance)"})
    assert status == 200
    outcome = after["approvals"][0]
    assert outcome["verdict"]["reason_code"] == "APPROVED_INTO_HARM"
    assert outcome["effects"][0]["approved_by"] == "Ingrid Dahl (finance)"
    assert after["verdict"] == "FAIL"
    assert call(path, {"run": 0, "call": 0, "decision": "reject", "approver": "x"})[0] == 400  # decided once
    assert call(f"{url}/api/world/runs/{run['id']}/verify")[1]["valid"] is True


def test_rejecting_a_held_call_keeps_it_from_running(base) -> None:
    url, _ = base
    run = call(f"{url}/api/world/runs", {"scenario": "payment-injection", "mode": "retest"})[1]
    after_policy = 1
    status, rec = call(f"{url}/api/world/runs/{run['id']}/approvals", {"run": after_policy, "call": 0, "decision": "reject", "approver": "Ingrid"})
    assert status == 200
    assert rec["approvals"][0]["verdict"]["reason_code"] == "REJECTED_BY_PERSON" and rec["approvals"][0]["effects"] == []
    assert rec["verdict"] == "PASS"
    # A call that already ran (the open-gateway run) cannot be "approved".
    assert call(f"{url}/api/world/runs/{run['id']}/approvals", {"run": 0, "call": 0, "decision": "approve", "approver": "x"})[0] == 400


def test_viewer_can_guard_single_tools(base) -> None:
    url, _ = base
    meta = call(f"{url}/api/world/meta")[1]
    assert meta["guardable"] == ["approve_payment", "cloud_admin", "lookup_case", "send_email"]

    open_ = {a["id"]: a for a in call(f"{url}/api/world/graph")[1]["agents"]}
    one = {a["id"]: a for a in call(f"{url}/api/world/graph?policy=custom&guard=approve_payment")[1]["agents"]}
    pay = one["payment-injection"]
    assert pay["score"] < open_["payment-injection"]["score"]
    assert {t["name"]: t["guarded"] for t in pay["tools"]}["approve_payment"] is True
    assert {t["name"]: t["guarded"] for t in pay["tools"]}["send_email"] is False
    email = {a["id"]: a for a in call(f"{url}/api/world/graph?policy=custom&guard=send_email")[1]["agents"]}
    assert pay["score"] < email["payment-injection"]["score"], "guarding the high-impact tool must count for more"
    # Guarding nothing is the open gateway.
    assert call(f"{url}/api/world/graph?policy=custom&guard=")[1]["policy"] == "open"

    status, run = call(f"{url}/api/world/runs", {"scenario": "payment-injection", "mode": "retest", "policy": "custom", "guard": ["approve_payment"]})
    assert status == 201
    assert [r["verdict"]["verdict"] for r in run["runs"]] == ["FAIL", "PASS"]
    assert run["runs"][1]["policy"] == "custom:approve_payment"

    # Guarding the wrong tool leaves the harm in place.
    status, run = call(f"{url}/api/world/runs", {"scenario": "payment-injection", "policy": "custom", "guard": ["send_email"]})
    assert status == 201 and run["verdict"] == "FAIL"


def test_custom_guard_only_accepts_reviewed_tools(base) -> None:
    url, _ = base
    assert call(f"{url}/api/world/graph?policy=custom&guard=read_invoice")[0] == 400
    assert call(f"{url}/api/world/runs", {"scenario": "payment-injection", "policy": "custom", "guard": [{"tool": "x"}]})[0] == 400
    assert call(f"{url}/api/world/runs", {"scenario": "payment-injection", "policy": "custom", "guard": "approve_payment"})[0] == 201
    assert call(f"{url}/api/world/runs", {"scenario": "payment-injection", "mode": "retest", "policy": "custom", "guard": []})[0] == 400
    assert call(f"{url}/api/world/runs", {"scenario": "payment-injection", "policy": "made-up"})[0] == 400


def test_remediation_propose_apply_rollback_over_http(base) -> None:
    url, runs = base
    status, view = call(f"{url}/api/world/remediation?profile=helio")
    assert status == 200 and view["synthetic"] is True and view["live"]["version"] == 0 and view["proposers"] == ["heuristic"]

    status, p = call(f"{url}/api/world/remediation", {"profile": "helio", "scenario": "helio-iam-escalation"})
    assert status == 201 and p["status"] == "proposed" and p["rule"]["type"] == "allow_actions"
    assert p["proof"]["attack"]["after"]["FAIL"] == 0 and "Cloud" in p["organisation"]

    assert call(f"{url}/api/world/remediation/{p['id']}/apply", {"profile": "helio", "approver": ""})[0] == 409
    status, p = call(f"{url}/api/world/remediation/{p['id']}/apply", {"profile": "helio", "approver": "Ingrid"})
    assert status == 200 and p["status"] == "applied"
    assert call(f"{url}/api/world/remediation?profile=helio")[1]["live"]["version"] == 1
    status, p = call(f"{url}/api/world/remediation/{p['id']}/rollback", {"profile": "helio", "approver": "Ingrid"})
    assert status == 200 and p["status"] == "rolled_back"

    status, got = call(f"{url}/api/world/remediation/{p['id']}?profile=helio")
    assert status == 200 and len(got["history"]) == 2
    with urllib.request.urlopen(f"{url}/api/world/remediation/{p['id']}/evidence.jsonl?profile=helio") as r:
        assert len(r.read().decode().splitlines()) == got["evidence"]["records"]
    assert call(f"{url}/api/world/remediation/{p['id']}?profile=nordvik")[0] == 404
    assert call(f"{url}/api/world/remediation", {"profile": "nordvik", "scenario": "helio-iam-escalation"})[0] == 400
    assert call(f"{url}/api/world/remediation", {"profile": "helio", "scenario": "helio-cross-tenant", "proposer": "live"})[0] == 400
    assert call(f"{url}/api/world/remediation/rem-20260101T000000-00000000/apply", {"profile": "helio", "approver": "x"})[0] == 404
    assert call(f"{url}/api/world/runs")[1]["runs"] == []
