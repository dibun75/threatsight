"""Model connections the attacks can run against.

Two sources, both chosen by the operator, never by a viewer's request:

* Local models: every model the local OpenAI-compatible server lists at ``{base}/models``
  (Ollama, vLLM, LM Studio, llama.cpp). Pulling a new model in Ollama makes it appear here.
* Added endpoints: the owner adds an agent or model endpoint (base URL, model name, optional key)
  on the Compare page. The web middleware lets only the owner add, check or remove them. Keys are
  kept in ``connections.json`` in the runs volume (mode 0600) and are never sent back to a browser.

Any agent that speaks the OpenAI chat-completions format with tool calls can be tested, and so can
any other agent behind a small wrapper speaking the threatsight-agent/1 protocol (see
``llm.AgentHTTPModel`` and ``examples/agent_adapter.py``): its own prompt and guardrails sit in front
of its model, and the Nordvik tools it calls act only on the synthetic world.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from threatsight_world.llm import AgentHTTPModel, ChatModel, OpenAICompatModel

LOCAL_PREFIX = "local:"
ENDPOINT_ID = re.compile(r"^ep-[0-9a-f]{8}$")
MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,119}$")
MAX_ENDPOINTS = 20
DISCOVERY_TTL = 30.0


@dataclass
class Endpoint:
    id: str
    label: str
    base_url: str
    model: str
    api_key: str | None = None
    # "openai": a model or agent speaking OpenAI chat completions at base_url.
    # "agent": your own agent at base_url speaking the threatsight-agent/1 protocol (see llm.AgentHTTPModel).
    protocol: str = "openai"

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "base_url": self.base_url, "model": self.model, "has_key": bool(self.api_key),
                "kind": "endpoint", "protocol": self.protocol}


PROTOCOLS = ("openai", "agent")


def validate_endpoint(body: dict[str, Any]) -> tuple[str, str, str, str | None, str]:
    label = str(body.get("label") or "").strip()
    base_url = str(body.get("base_url") or "").strip().rstrip("/")
    protocol = str(body.get("protocol") or "openai")
    model = str(body.get("model") or "").strip() or ("agent" if protocol == "agent" else "")
    api_key = str(body.get("api_key") or "").strip() or None
    if not label or len(label) > 80:
        raise ValueError("give the endpoint a name of at most 80 characters")
    if protocol not in PROTOCOLS:
        raise ValueError(f"protocol must be one of {list(PROTOCOLS)}")
    url = urlparse(base_url)
    if url.scheme not in {"http", "https"} or not url.hostname or len(base_url) > 300 or url.username or url.password:
        raise ValueError("URL must be an http(s) address such as http://host:11434/v1, without a user or password in it")
    if not MODEL_NAME.match(model):
        raise ValueError("model name is required (letters, digits and . _ : / @ + -)")
    if api_key is not None and len(api_key) > 500:
        raise ValueError("API key is too long")
    return label, base_url, model, api_key, protocol


class Connections:
    def __init__(self, data_dir: Path, local_base: str, local_model: str | None, local_key: str | None) -> None:
        self.path = data_dir / "connections.json"
        self.local_base = local_base.rstrip("/")
        self.local_model = local_model
        self.local_key = local_key
        self._lock = threading.Lock()
        self._discovered: tuple[float, list[str]] | None = None

    def configure(self, local_base: str, local_model: str | None, local_key: str | None) -> None:
        """Point at a different local server (the Settings page saved one). Rediscovers on next use."""
        self.local_base = local_base.rstrip("/")
        self.local_model = local_model
        self.local_key = local_key
        self._discovered = None

    # Local models ---------------------------------------------------------------------------

    def local_models(self) -> list[str]:
        """Models the local server lists, plus THREATSIGHT_LLM_MODEL. Empty when nothing is configured."""
        if not self.local_model:
            return []
        # No discovery yet means discover now. A (0.0, []) sentinel skipped discovery whenever
        # time.monotonic() (seconds since boot) was below the TTL, e.g. on a freshly started CI runner.
        if self._discovered is None or time.monotonic() - self._discovered[0] > DISCOVERY_TTL:
            cached = self._discover()
            self._discovered = (time.monotonic(), cached)
        else:
            cached = self._discovered[1]
        return sorted({self.local_model, *cached})

    def _discover(self) -> list[str]:
        req = urllib.request.Request(f"{self.local_base}/models", headers=self._headers(self.local_key))
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
            names = [str(m.get("id", "")) for m in data.get("data", []) if isinstance(m, dict)]
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, AttributeError):
            return []
        # Embedding-only models cannot call tools; leave them out of the picker.
        return [n for n in names if MODEL_NAME.match(n) and "embed" not in n.lower()]

    @staticmethod
    def _headers(key: str | None) -> dict[str, str]:
        return {"Authorization": f"Bearer {key}"} if key else {}

    # Added endpoints ------------------------------------------------------------------------

    def endpoints(self) -> list[Endpoint]:
        if not self.path.is_file():
            return []
        try:
            rows = json.loads(self.path.read_text())
            return [Endpoint(**r) for r in rows if isinstance(r, dict) and ENDPOINT_ID.match(str(r.get("id", "")))]
        except (OSError, ValueError, TypeError):
            return []

    def _save(self, items: list[Endpoint]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([asdict(e) for e in items], indent=2))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def add(self, body: dict[str, Any]) -> Endpoint:
        label, base_url, model, api_key, protocol = validate_endpoint(body)
        with self._lock:
            items = self.endpoints()
            if len(items) >= MAX_ENDPOINTS:
                raise ValueError(f"at most {MAX_ENDPOINTS} endpoints; remove one first")
            ep = Endpoint(f"ep-{uuid.uuid4().hex[:8]}", label, base_url, model, api_key, protocol)
            self._save([*items, ep])
        return ep

    def remove(self, endpoint_id: str) -> bool:
        with self._lock:
            items = self.endpoints()
            kept = [e for e in items if e.id != endpoint_id]
            if len(kept) == len(items):
                return False
            self._save(kept)
        return True

    # Lookup ---------------------------------------------------------------------------------

    def options(self) -> list[dict[str, Any]]:
        """Every live connection a viewer can pick, without keys."""
        local = [{"id": f"{LOCAL_PREFIX}{m}", "label": m, "model": m, "kind": "local"} for m in self.local_models()]
        return local + [e.public() for e in self.endpoints()]

    def model(self, connection_id: str) -> ChatModel:
        if connection_id.startswith(LOCAL_PREFIX):
            name = connection_id[len(LOCAL_PREFIX):]
            if name not in self.local_models():
                raise ValueError(f"no local model {name!r}; pull it in Ollama first")
            return OpenAICompatModel(self.local_base, name, self.local_key, timeout=180.0)
        for e in self.endpoints():
            if e.id == connection_id and e.protocol == "agent":
                return AgentHTTPModel(e.base_url, e.api_key, timeout=180.0, name=e.label)
            if e.id == connection_id:
                m = OpenAICompatModel(e.base_url, e.model, e.api_key, timeout=180.0)
                m.name = f"endpoint:{e.label}"
                return m
        raise ValueError(f"unknown connection {connection_id!r}")

    def label(self, connection_id: str) -> str:
        for o in self.options():
            if o["id"] == connection_id:
                return str(o["label"])
        return connection_id


CHECK_TOOL = {
    "type": "function",
    "function": {
        "name": "lookup_invoice",
        "description": "Look up an invoice by its number.",
        "parameters": {"type": "object", "properties": {"invoice_id": {"type": "string"}}, "required": ["invoice_id"]},
    },
}


def check(model: ChatModel) -> dict[str, Any]:
    """One short request: is the endpoint reachable, and does it call tools?"""
    started = time.monotonic()
    messages = [
        {"role": "system", "content": "You are a finance assistant. Use the tools you have."},
        {"role": "user", "content": "Look up invoice 4471."},
    ]
    try:
        reply = model.complete(messages, [CHECK_TOOL])
    except (ConnectionError, ValueError) as exc:
        return {"reachable": False, "tool_calling": False, "error": str(exc)[:300], "ms": round((time.monotonic() - started) * 1000)}
    calls = [c.name for c in reply.tool_calls]
    return {
        "reachable": True,
        "tool_calling": "lookup_invoice" in calls,
        "error": None if calls else "it answered in text and did not call the tool; attacks will mostly show as refused",
        "ms": round((time.monotonic() - started) * 1000),
    }
