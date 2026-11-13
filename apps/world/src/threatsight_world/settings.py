"""Model settings an administrator changes from the web Settings page.

Environment variables stay the defaults (``THREATSIGHT_LLM_BASE_URL``, ``THREATSIGHT_LLM_MODEL``,
``THREATSIGHT_LLM_API_KEY`` and ``THREATSIGHT_REMEDIATION_MODEL``). A saved value overrides its
variable until it is cleared again. Settings live in ``model-settings.json`` in the runs volume
(mode 0600), next to ``connections.json``; the local server's key is never sent back to a browser.

Three choices are stored:

* the local model server (Ollama, vLLM, LM Studio): its base URL, its default model and an optional key;
* the agent model: which connection the agents run on when a page asks for the default ("live");
* the fix proposer: which connection writes guardrail-fix proposals.

The last two name a connection id (``local:<model>`` or an added endpoint ``ep-…``), so OpenRouter,
OpenAI or any other OpenAI-compatible endpoint added on this page can drive either one.
"""
from __future__ import annotations

import json
import os
import re
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from threatsight_world.connections import ENDPOINT_ID, LOCAL_PREFIX, MODEL_NAME

FIELDS = ("local_base", "local_model", "local_key", "agent", "proposer")
CONNECTION_ID = re.compile(rf"^(?:{re.escape(LOCAL_PREFIX)}[A-Za-z0-9][A-Za-z0-9._:/@+-]{{0,119}}|ep-[0-9a-f]{{8}})$")
LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def env_defaults() -> dict[str, str | None]:
    return {
        "local_base": os.environ.get("THREATSIGHT_LLM_BASE_URL", "http://localhost:11434/v1"),
        "local_model": os.environ.get("THREATSIGHT_LLM_MODEL") or None,
        "local_key": os.environ.get("THREATSIGHT_LLM_API_KEY") or None,
        "agent": None,
        "proposer": f"{LOCAL_PREFIX}{os.environ['THREATSIGHT_REMEDIATION_MODEL']}" if os.environ.get("THREATSIGHT_REMEDIATION_MODEL") else None,
    }


def check_base_url(base_url: str) -> str:
    base = base_url.strip().rstrip("/")
    url = urlparse(base)
    if url.scheme not in {"http", "https"} or not url.hostname or len(base) > 300 or url.username or url.password:
        raise ValueError("URL must be an http(s) address such as http://172.17.0.1:11434/v1, without a user or password in it")
    return base


class ModelSettings:
    def __init__(self, data_dir: Path, defaults: dict[str, str | None]) -> None:
        self.path = data_dir / "model-settings.json"
        self.defaults = defaults
        self._lock = threading.Lock()

    def saved(self) -> dict[str, str]:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return {k: str(v) for k, v in data.items() if k in FIELDS and isinstance(v, str) and v} if isinstance(data, dict) else {}

    def effective(self) -> dict[str, str | None]:
        saved = self.saved()
        return {k: saved.get(k, self.defaults.get(k)) for k in FIELDS}

    def update(self, body: dict[str, Any]) -> dict[str, str]:
        """Apply a partial change. A field set to null or "" goes back to its environment default.

        ``local_key`` is write-only: leaving it out keeps the saved key, and ``clear_local_key`` removes it.
        """
        changes: dict[str, str | None] = {}
        for key in ("local_base", "local_model", "agent", "proposer"):
            if key not in body:
                continue
            value = str(body[key] or "").strip()
            if not value:
                changes[key] = None
            elif key == "local_base":
                changes[key] = check_base_url(value)
            elif key == "local_model":
                if not MODEL_NAME.match(value):
                    raise ValueError("model name may use letters, digits and . _ : / @ + -")
                changes[key] = value
            else:
                if not CONNECTION_ID.match(value):
                    raise ValueError(f"{key} must name a connection such as local:qwen2.5:7b-instruct or an added endpoint")
                changes[key] = value
        if body.get("clear_local_key"):
            changes["local_key"] = None
        elif str(body.get("local_key") or "").strip():
            key = str(body["local_key"]).strip()
            if len(key) > 500:
                raise ValueError("API key is too long")
            changes["local_key"] = key
        with self._lock:
            saved = self.saved()
            for k, v in changes.items():
                if v is None:
                    saved.pop(k, None)
                else:
                    saved[k] = v
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(saved, indent=2, sort_keys=True))
            os.chmod(tmp, 0o600)
            tmp.replace(self.path)
        return saved

    def view(self) -> dict[str, Any]:
        """What the Settings page shows. Keys are reported only as present or not."""
        saved, eff = self.saved(), self.effective()
        return {
            "local": {"base_url": eff["local_base"], "model": eff["local_model"], "has_key": bool(eff["local_key"]),
                      "key_source": "saved" if "local_key" in saved else ("environment" if self.defaults.get("local_key") else None)},
            "agent": eff["agent"], "proposer": eff["proposer"],
            "saved": sorted(k for k in saved if k != "local_key") + (["local_key"] if "local_key" in saved else []),
            "defaults": {"local_base": self.defaults.get("local_base"), "local_model": self.defaults.get("local_model"),
                         "has_key": bool(self.defaults.get("local_key")), "proposer": self.defaults.get("proposer")},
        }


def probe(base_url: str, key: str | None) -> dict[str, Any]:
    """Can the world service reach a local model server, and which models does it list?

    The error says where the address is resolved from, because ``localhost`` inside the world
    container is the container itself, not the machine running Ollama.
    """
    try:
        base = check_base_url(base_url)
    except ValueError as exc:
        return {"reachable": False, "models": [], "error": str(exc)}
    req = urllib.request.Request(f"{base}/models", headers={"Authorization": f"Bearer {key}"} if key else {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        names = sorted(str(m.get("id", "")) for m in data.get("data", []) if isinstance(m, dict))
    except urllib.error.HTTPError as exc:
        hint = " The server wants an API key." if exc.code in {401, 403} else " Check that the address ends in /v1."
        return {"reachable": False, "models": [], "error": f"{base}/models answered HTTP {exc.code}.{hint}"}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, AttributeError) as exc:
        reason = getattr(exc, "reason", exc)
        msg = f"The world service could not reach {base}: {reason}."
        if (urlparse(base).hostname or "") in LOOPBACK:
            msg += (" localhost here means the world service's own container. Use the host's address instead:"
                    " http://host.docker.internal:11434/v1 on Docker Desktop, or the Docker bridge address"
                    " (often http://172.17.0.1:11434/v1) on Linux, with Ollama listening on that interface.")
        return {"reachable": False, "models": [], "error": msg}
    models = [n for n in names if MODEL_NAME.match(n) and "embed" not in n.lower()]
    return {"reachable": True, "models": models, "error": None if models else "The server answered but lists no chat models. Pull one, for example ollama pull qwen2.5:7b-instruct."}


__all__ = ["ModelSettings", "probe", "env_defaults", "check_base_url", "CONNECTION_ID", "ENDPOINT_ID"]
