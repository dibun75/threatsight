"""Runs exported as Inspect AI evaluation logs: per run, all runs, and from the CLI suite."""
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from threatsight_world import cli
from threatsight_world.inspect_log import SCORER, eval_log, filename
from threatsight_world.server import Config, serve


@pytest.fixture()
def world(tmp_path: Path):
    cfg = Config(tmp_path / "runs", "http://127.0.0.1:9/v1", None, None)
    httpd = serve(cfg, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/api/world"
    httpd.shutdown()


def post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def get(url: str) -> tuple[int, dict, str]:
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.status, json.loads(r.read()), r.headers.get("Content-Disposition", "")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), ""


def check_shape(log: dict) -> None:
    """The fields Inspect's reader requires, without needing Inspect installed."""
    assert log["version"] == 2 and log["status"] == "success"
    for key in ("created", "task", "dataset", "model", "config"):
        assert key in log["eval"]
    assert log["eval"]["created"].endswith("+00:00") and "/" in log["eval"]["model"]
    assert log["eval"]["metadata"]["synthetic"] is True
    ids = [s["id"] for s in log["samples"]]
    assert len(ids) == len(set(ids)) == log["results"]["total_samples"] == log["eval"]["dataset"]["samples"]
    for s in log["samples"]:
        assert s["epoch"] == 1 and s["input"] and s["target"] and s["metadata"]["synthetic"] is True
        assert s["scores"][SCORER]["value"] in {"C", "I", "N"}
        assert s["messages"][0]["role"] == "system" and s["messages"][1]["role"] == "user"
        calls = {c["id"] for m in s["messages"] if m["role"] == "assistant" for c in m.get("tool_calls", [])}
        assert all(m["tool_call_id"] in calls for m in s["messages"] if m["role"] == "tool")
    try:
        from inspect_ai.log import EvalLog
    except ImportError:
        return
    parsed = EvalLog.model_validate(log)
    assert len(parsed.samples) == len(log["samples"])


def test_one_retest_becomes_two_scored_samples(world) -> None:
    run = post(f"{world}/runs", {"scenario": "payment-injection", "model": "scripted", "mode": "retest"})
    status, log, disposition = get(f"{world}/runs/{run['id']}/inspect.json")
    assert status == 200 and disposition.endswith('.json"') and "threatsight-agent-assessment" in disposition
    check_shape(log)
    before, after = log["samples"]
    assert (before["scores"][SCORER]["answer"], after["scores"][SCORER]["answer"]) == ("FAIL", "PASS")
    assert before["metadata"]["policy"] == "open" and after["metadata"]["policy"] == "nordvik-hardened"
    assert after["metadata"]["utility"] and after["metadata"]["mitre_atlas"]
    held = next(m for m in after["messages"] if m["role"] == "tool")
    assert held["error"]["type"] == "approval" and held["metadata"]["gateway"]["hold"] is True
    assert log["results"]["scores"][0]["metrics"]["pass_rate"]["value"] == 0.5
    assert log["eval"]["model"] == "threatsight/scripted"


def test_an_approved_held_payment_is_scored_as_the_fail_it_caused(world) -> None:
    run = post(f"{world}/runs", {"scenario": "payment-injection", "model": "scripted", "mode": "retest"})
    post(f"{world}/runs/{run['id']}/approvals", {"run": 1, "call": 0, "decision": "approve", "approver": "Kari Nordmann"})
    _, log, _ = get(f"{world}/runs/{run['id']}/inspect.json")
    after = log["samples"][1]
    assert after["scores"][SCORER]["value"] == "I" and after["metadata"]["reason_code"] == "APPROVED_INTO_HARM"
    assert after["metadata"]["verdict_before_approval"]["reason_code"] == "HELD_FOR_APPROVAL"
    assert after["metadata"]["approvals"][0]["approver"] == "Kari Nordmann"


def test_all_runs_export_as_one_log(world) -> None:
    assert get(f"{world}/export/runs.inspect.json")[0] == 404
    post(f"{world}/runs", {"scenario": "payment-injection", "model": "scripted", "policy": "open"})
    post(f"{world}/runs", {"scenario": "helio-cross-tenant", "model": "scripted", "policy": "helio-hardened"})
    status, log, _ = get(f"{world}/export/runs.inspect.json")
    assert status == 200
    check_shape(log)
    assert len(log["samples"]) == 2 and len(log["eval"]["metadata"]["runs"]) == 2
    assert log["eval"]["dataset"]["name"] == "threatsight-world/helio+nordvik"
    assert get(f"{world}/runs/20990101T000000-00000000/inspect.json")[0] == 404


def test_mixed_models_are_named_per_sample() -> None:
    a = {"model": "scripted", "policy": "open", "verdict": {"verdict": "FAIL"}, "transcript": [{"type": "input", "text": "hi"}]}
    records = [{"id": "r1", "created": "2026-11-08T10:00:00Z", "scenario": "payment-injection", "runs": [a]},
               {"id": "r2", "created": "2026-11-08T11:00:00Z", "scenario": "payment-injection", "runs": [{**a, "model": "ollama/qwen2.5:7b"}]}]
    log = eval_log(records)
    assert log["eval"]["model"] == "threatsight/mixed"
    assert [s["output"]["model"] for s in log["samples"]] == ["threatsight/scripted", "ollama/qwen2.5:7b"]
    assert filename(log).startswith("2026-11-08T10-00-00+00-00_threatsight-agent-assessment_")


def test_cli_suite_writes_an_inspect_log(tmp_path: Path) -> None:
    out = tmp_path / "logs" / "suite.json"
    assert cli.main(["suite", "--profile", "all", "--inspect-log", str(out)]) == 0
    log = json.loads(out.read_text())
    check_shape(log)
    assert len(log["samples"]) == 8 and log["results"]["scores"][0]["metrics"]["accuracy"]["value"] == 1.0
