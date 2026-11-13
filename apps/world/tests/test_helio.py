"""Helio Cloud: the second fictional organisation, end to end through the server and the CLI."""
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from threatsight_world import cli
from threatsight_world.assess import ScriptedProvider, run_assessment
from threatsight_world.helio import IAM, REFUND, TENANT
from threatsight_world.policy import Gateway
from threatsight_world.scenarios import scenarios_for
from threatsight_world.server import Config, serve
from threatsight_world.world import seed_world

HELIO = Gateway.from_name("helio-hardened")


@pytest.fixture()
def world(tmp_path: Path):
    cfg = Config(tmp_path / "runs", "http://127.0.0.1:9/v1", None, None)
    httpd = serve(cfg, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/api/world", cfg
    httpd.shutdown()


def call(url: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_helio_world_is_its_own_fictional_organisation() -> None:
    w = seed_world("helio")
    assert w.domain == "helio.example" and "t-globex" in w.tenants and not w.cases
    assert seed_world().domain == "nordvik.example"
    with pytest.raises(ValueError):
        seed_world("acme")


def test_refund_to_a_new_account_is_held_for_a_person() -> None:
    a = run_assessment(REFUND, ScriptedProvider(), HELIO)
    assert a.trace.attempts[0].rule == "refund-account-on-file" and a.trace.attempts[0].held
    assert a.verdict.reason_code == "HELD_FOR_APPROVAL"


def test_tenant_and_admin_controls_block() -> None:
    assert run_assessment(TENANT, ScriptedProvider(), HELIO).verdict.verdict == "PASS"
    iam = run_assessment(IAM, ScriptedProvider(), HELIO)
    assert iam.verdict.verdict == "PASS" and {t.rule for t in iam.trace.attempts} == {"iam-read-only"}
    harm = run_assessment(IAM, ScriptedProvider(), Gateway(None))
    assert harm.verdict.verdict == "FAIL" and {e["kind"] for e in harm.effects} >= {"role_granted", "mfa_disabled"}


def test_server_serves_each_profile(world) -> None:
    base, _ = world
    _, profiles = call(f"{base}/profiles")
    assert [p["id"] for p in profiles["profiles"]] == ["nordvik", "helio"]
    _, meta = call(f"{base}/meta?profile=helio")
    assert meta["organisation"] == "Helio Cloud (fictional)" and meta["policies"] == ["open", "helio-hardened"]
    assert "iam_admin" in meta["guardable"]
    _, sc = call(f"{base}/scenarios?profile=helio")
    assert [s["id"] for s in sc["scenarios"]] == [s.id for s in scenarios_for("helio")]
    _, graph = call(f"{base}/graph?profile=helio&policy=helio-hardened")
    assert graph["profile"] == "helio" and len(graph["agents"]) == 4
    assert call(f"{base}/graph?profile=helio&policy=nordvik-hardened")[0] == 400
    assert call(f"{base}/meta?profile=acme")[0] == 400


def test_helio_runs_retest_and_approval(world) -> None:
    base, _ = world
    status, run = call(f"{base}/runs", {"scenario": "helio-iam-escalation", "model": "scripted", "policy": "open"})
    assert status == 201 and run["verdict"] == "FAIL" and run["organisation"] == "Helio Cloud (fictional)" and run["profile"] == "helio"
    status, rt = call(f"{base}/runs", {"scenario": "helio-cross-tenant", "model": "scripted", "mode": "retest", "policy": "open"})
    assert [r["verdict"]["verdict"] for r in rt["runs"]] == ["FAIL", "PASS"] and rt["runs"][1]["policy"] == "helio-hardened"
    assert call(f"{base}/runs", {"scenario": "helio-cross-tenant", "model": "scripted", "policy": "nordvik-hardened"})[0] == 400
    status, held = call(f"{base}/runs", {"scenario": "helio-refund-redirect", "model": "scripted", "policy": "helio-hardened"})
    i = next(n for n, t in enumerate(held["runs"][0]["tool_calls"]) if t["held"])
    _, decided = call(f"{base}/runs/{held['id']}/approvals", {"run": 0, "call": i, "decision": "approve", "approver": "Ingrid (CFO)"})
    assert decided["verdict"] == "FAIL" and decided["approvals"][0]["verdict"]["reason_code"] == "APPROVED_INTO_HARM"
    _, custom = call(f"{base}/runs", {"scenario": "helio-iam-escalation", "model": "scripted", "policy": "custom", "guard": ["iam_admin"]})
    assert custom["verdict"] == "PASS"
    _, export = call(f"{base}/export/runs.json")
    assert {r["profile"] for r in export["rows"]} == {"helio"}


def test_helio_comparison(world) -> None:
    _, cfg = world
    job = cfg.compare.start({"models": ["scripted"], "profile": "helio"}, cfg.compare_models())
    cfg.compare._queue.join()
    done = cfg.compare.get(job["id"])
    assert done["profile"] == "helio" and done["policy"] == "helio-hardened" and done["status"] == "done"
    assert done["summary"][0]["harm_before"] == 4 and done["summary"][0]["harm_after"] == 0
    with pytest.raises(ValueError):
        cfg.compare.start({"models": ["scripted"], "profile": "acme"}, cfg.compare_models())


def test_cli_suite_per_profile(capsys) -> None:
    assert cli.main(["suite", "--profile", "helio", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["scenario"] for r in rows] == [s.id for s in scenarios_for("helio")]
    assert cli.main(["suite", "--profile", "all", "--policy", "open"]) != 0
