"""Model settings saved from the web Settings page override the environment defaults."""
import json
import threading
from pathlib import Path

from test_compare import FakeModels, call, fake_llm  # noqa: F401  (fixture)
from threatsight_world.server import Config, serve
from threatsight_world.settings import ModelSettings, probe


def start(tmp_path: Path, base: str, model: str | None):
    httpd = serve(Config(tmp_path / "runs", base, model, None), "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/api/world"


def test_saving_a_local_server_turns_on_live_models(tmp_path: Path, fake_llm: str) -> None:  # noqa: F811
    httpd, url = start(tmp_path, "http://127.0.0.1:9/v1", None)
    try:
        assert call(f"{url}/meta")[1]["models"] == ["scripted"]
        status, view = call(f"{url}/settings/probe", {"local_base": fake_llm})
        assert status == 200 and view["reachable"] and view["models"] == ["llama3.1:8b", "qwen2.5:7b"]
        status, view = call(f"{url}/settings", {"local_base": fake_llm, "local_model": "qwen2.5:7b", "local_key": "sk-local-999"})
        assert status == 200 and view["local"]["base_url"] == fake_llm and view["local"]["has_key"] is True
        assert "sk-local-999" not in json.dumps(view) and "sk-local-999" not in json.dumps(call(f"{url}/settings")[1])
        assert (tmp_path / "runs" / "model-settings.json").stat().st_mode & 0o077 == 0
        meta = call(f"{url}/meta")[1]
        assert "live" in meta["models"] and meta["live_model"] == "qwen2.5:7b"
        assert call(f"{url}/remediation?profile=helio")[1]["proposers"] == ["heuristic", "live"]

        # Point the agents at one model and the proposer at another.
        call(f"{url}/settings", {"agent": "local:llama3.1:8b", "proposer": "local:qwen2.5:7b"})
        view = call(f"{url}/settings")[1]
        assert view["effective"] == {"agent": "local:llama3.1:8b", "proposer": "local:qwen2.5:7b"}
        assert call(f"{url}/meta")[1]["live_model"] == "llama3.1:8b"
        assert call(f"{url}/remediation?profile=helio")[1]["live_model"] == "qwen2.5:7b"

        # Clearing a field goes back to the environment default; the key survives until cleared.
        view = call(f"{url}/settings", {"local_base": "", "local_model": None, "agent": "", "proposer": ""})[1]
        assert view["local"]["base_url"] == "http://127.0.0.1:9/v1" and view["local"]["model"] is None and view["local"]["has_key"] is True
        assert call(f"{url}/settings", {"clear_local_key": True})[1]["local"]["has_key"] is False
        assert call(f"{url}/meta")[1]["models"] == ["scripted"]
    finally:
        httpd.shutdown()


def test_an_added_endpoint_can_be_the_agent_and_the_proposer(tmp_path: Path, fake_llm: str) -> None:  # noqa: F811
    httpd, url = start(tmp_path, "http://127.0.0.1:9/v1", None)
    try:
        ep = call(f"{url}/connections", {"label": "OpenRouter", "base_url": fake_llm, "model": "qwen/qwen-2.5-72b-instruct", "api_key": "sk-or-1"})[1]["connection"]["id"]
        call(f"{url}/settings", {"agent": ep, "proposer": ep})
        meta = call(f"{url}/meta")[1]
        assert "live" in meta["models"] and ep not in meta["models"] and meta["live_model"] == "OpenRouter"
        status, run = call(f"{url}/runs", {"scenario": "payment-injection", "model": "live"})
        assert status == 201
        # Removing the endpoint falls back to nothing configured rather than a dangling id.
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(f"{url}/connections/{ep}", method="DELETE")).read()
        assert call(f"{url}/settings")[1]["effective"] == {"agent": None, "proposer": None}
    finally:
        httpd.shutdown()


def test_bad_settings_are_refused(tmp_path: Path) -> None:
    httpd, url = start(tmp_path, "http://127.0.0.1:9/v1", None)
    try:
        assert call(f"{url}/settings", {"local_base": "file:///etc/passwd"})[0] == 400
        assert call(f"{url}/settings", {"local_base": "http://user:pw@host/v1"})[0] == 400
        assert call(f"{url}/settings", {"local_model": "bad model name"})[0] == 400
        assert call(f"{url}/settings", {"agent": "../../etc"})[0] == 400
        assert call(f"{url}/settings", {"local_key": "x" * 501})[0] == 400
    finally:
        httpd.shutdown()


def test_probe_explains_localhost_inside_a_container() -> None:
    r = probe("http://localhost:9/v1", None)
    assert r["reachable"] is False and "172.17.0.1" in r["error"] and "host.docker.internal" in r["error"]


def test_key_source_is_reported_without_the_key(tmp_path: Path) -> None:
    s = ModelSettings(tmp_path, {"local_base": "http://a:1/v1", "local_model": None, "local_key": "env-key"})
    assert s.view()["local"]["key_source"] == "environment"
    s.update({"local_key": "saved"})
    assert s.effective()["local_key"] == "saved" and s.view()["local"]["key_source"] == "saved"
