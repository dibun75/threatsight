"""Model connections and the model comparison table."""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from threatsight_world.connections import Connections, validate_endpoint
from threatsight_world.server import Config, serve


class FakeModels(BaseHTTPRequestHandler):
    """An OpenAI-compatible server: lists two models, calls lookup_invoice when offered, else refuses."""

    def log_message(self, *args: object) -> None:
        pass

    def _json(self, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._json({"data": [{"id": "qwen2.5:7b"}, {"id": "llama3.1:8b"}, {"id": "nomic-embed-text"}]})

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        names = [t["function"]["name"] for t in body.get("tools", [])]
        if names == ["lookup_invoice"]:
            msg = {"content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "lookup_invoice", "arguments": "{\"invoice_id\": \"4471\"}"}}]}
        else:
            msg = {"content": "I will not do that without a person checking it.", "tool_calls": []}
        self._json({"choices": [{"message": msg}]})


@pytest.fixture()
def fake_llm():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeModels)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/v1"
    httpd.shutdown()


@pytest.fixture()
def world(tmp_path: Path, fake_llm: str):
    httpd = serve(Config(tmp_path / "runs", fake_llm, "qwen2.5:7b", None), "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/api/world", tmp_path / "runs", fake_llm
    httpd.shutdown()


def call(url: str, body: dict | None = None, method: str | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def wait_done(url: str, job_id: str) -> dict:
    for _ in range(200):
        _, job = call(f"{url}/compare/{job_id}")
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(0.05)
    raise AssertionError("comparison did not finish")


def test_local_models_are_discovered_without_embedding_models(world) -> None:
    url, _, _ = world
    ids = [c["id"] for c in call(f"{url}/connections")[1]["connections"]]
    assert ids == ["local:llama3.1:8b", "local:qwen2.5:7b"]
    models = call(f"{url}/meta")[1]["models"]
    assert "live" in models and "local:llama3.1:8b" in models and "local:qwen2.5:7b" not in models


def test_endpoint_is_added_checked_and_removed_without_leaking_the_key(world) -> None:
    url, runs, fake = world
    status, body = call(f"{url}/connections", {"label": "Our finance agent", "base_url": fake, "model": "agent-v2", "api_key": "sk-secret-123"})
    assert status == 201 and body["connection"]["has_key"] is True
    ep = body["connection"]["id"]
    listing = json.dumps(call(f"{url}/connections")[1])
    assert "sk-secret-123" not in listing and "Our finance agent" in listing
    assert (runs / "connections.json").stat().st_mode & 0o077 == 0
    status, chk = call(f"{url}/connections/{ep}/check", {})
    assert status == 200 and chk["reachable"] and chk["tool_calling"]
    assert call(f"{url}/connections/{ep}", method="DELETE")[0] == 200
    assert call(f"{url}/connections/{ep}", method="DELETE")[0] == 404


def test_unreachable_endpoint_check_says_so(world) -> None:
    url, _, _ = world
    _, body = call(f"{url}/connections", {"label": "Down", "base_url": "http://127.0.0.1:9/v1", "model": "x"})
    _, chk = call(f"{url}/connections/{body['connection']['id']}/check", {})
    assert chk["reachable"] is False and chk["error"]


@pytest.mark.parametrize(
    "body",
    [
        {"label": "", "base_url": "http://h/v1", "model": "m"},
        {"label": "x", "base_url": "file:///etc/passwd", "model": "m"},
        {"label": "x", "base_url": "http://user:pw@h/v1", "model": "m"},
        {"label": "x", "base_url": "http://h/v1", "model": "bad model name"},
    ],
)
def test_bad_endpoints_are_refused(body: dict) -> None:
    with pytest.raises(ValueError):
        validate_endpoint(body)


def test_comparison_fills_every_cell_and_summarises(world) -> None:
    url, runs, _ = world
    status, job = call(f"{url}/compare", {"models": ["scripted", "local:qwen2.5:7b"]})
    assert status == 202 and job["total"] == 8
    job = wait_done(url, job["id"])
    assert job["status"] == "done" and job["done"] == 8 and job["evidence"]["valid"]
    by = {s["model"]: s for s in job["summary"]}
    # The scripted baseline does harm on every attack and the policy stops all of it.
    assert by["scripted"]["harm_before"] == 4 and by["scripted"]["harm_after"] == 0
    # The fake model refuses in text, so nothing is harmed, and the cell says it never tried.
    assert by["local:qwen2.5:7b"]["harm_before"] == 0
    cell = job["cells"]["payment-injection|local:qwen2.5:7b"]
    assert cell["before"]["reason_code"] == "NO_ATTEMPT" and "person" in cell["before"]["said"]
    assert (runs / "compare" / f"{job['id']}.evidence.jsonl").is_file()
    assert call(f"{url}/compare")[1]["comparisons"][0]["id"] == job["id"]


def test_comparison_refuses_unknown_or_too_many_models(world) -> None:
    url, _, _ = world
    assert call(f"{url}/compare", {"models": ["local:gpt-evil"]})[0] == 400
    assert call(f"{url}/compare", {"models": []})[0] == 400
    assert call(f"{url}/compare/cmp-../../etc")[0] == 404


def test_unreachable_model_marks_cells_without_stopping_the_job(tmp_path: Path) -> None:
    cfg = Config(tmp_path / "runs", "http://127.0.0.1:9/v1", None, None)
    ep = cfg.connections.add({"label": "Down", "base_url": "http://127.0.0.1:9/v1", "model": "x"})
    job = cfg.compare.start({"models": ["scripted", ep.id]}, cfg.compare_models())
    cfg.compare._queue.join()
    job = cfg.compare.get(job["id"])
    assert job["status"] == "done"
    assert all("error" in job["cells"][f"{s['id']}|{ep.id}"] for s in job["scenarios"])
    assert {s["model"]: s["errors"] for s in job["summary"]} == {"scripted": 0, ep.id: 4}


def test_interrupted_comparisons_are_marked_after_restart(tmp_path: Path) -> None:
    cfg = Config(tmp_path / "runs", "http://127.0.0.1:9/v1", None, None)
    cfg.compare._ensure_worker = lambda: None  # never run it
    job = cfg.compare.start({"models": ["scripted"]}, cfg.compare_models())
    Config(tmp_path / "runs", "http://127.0.0.1:9/v1", None, None).compare.recover()
    assert cfg.compare.get(job["id"])["status"] == "interrupted"


def test_connections_need_a_configured_local_model(tmp_path: Path, fake_llm: str) -> None:
    assert Connections(tmp_path, fake_llm, None, None).local_models() == []


def test_first_discovery_runs_even_just_after_boot(world, monkeypatch) -> None:
    """time.monotonic() counts from boot; a fresh CI runner can sit below the discovery TTL."""
    from threatsight_world import connections as module

    monkeypatch.setattr(module.time, "monotonic", lambda: 1.0)
    _, _, fake = world
    conn = module.Connections(Path("/nonexistent"), fake, "qwen2.5:7b", None)
    assert conn.local_models() == ["llama3.1:8b", "qwen2.5:7b"]
