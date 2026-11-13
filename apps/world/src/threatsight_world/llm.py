"""Chat models: a deterministic scripted model, a replay model and an OpenAI-compatible client.

The OpenAI-compatible client works with Ollama, vLLM, llama.cpp server, LM Studio and hosted APIs.
It uses only the standard library.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class AssistantMessage:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"content": self.content, "tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments} for c in self.tool_calls]}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AssistantMessage":
        return cls(d.get("content", ""), [ToolCall(c["id"], c["name"], c["arguments"]) for c in d.get("tool_calls", [])])


class ChatModel(Protocol):
    name: str

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AssistantMessage: ...


class ScriptedModel:
    """Returns pre-written turns in order. It never reads the conversation, so runs are repeatable."""

    def __init__(self, turns: list[AssistantMessage], name: str = "scripted") -> None:
        self.name = name
        self._turns = list(turns)
        self._i = 0

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AssistantMessage:
        if self._i >= len(self._turns):
            return AssistantMessage("", [])
        turn = self._turns[self._i]
        self._i += 1
        return turn


class OpenAICompatModel:
    def __init__(self, base_url: str, model: str, api_key: str | None = None, timeout: float = 120.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.name = f"openai:{model}"

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AssistantMessage:
        body = json.dumps({"model": self.model, "messages": messages, "tools": tools, "temperature": 0}).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"model endpoint {self.base_url} unreachable: {exc}") from exc
        return parse_chat_response(data)

    def complete_json(self, messages: list[dict[str, Any]], temperature: float = 0.0, schema: dict[str, Any] | None = None) -> str:
        """One plain chat turn that asks for a JSON object, with no tools. Returns the raw text.

        With ``schema``, the server is asked to constrain generation to it (``json_schema`` response
        format; Ollama, vLLM and llama.cpp support it). A server that refuses that format with an HTTP
        4xx is asked again for a plain JSON object. The caller validates the text either way.
        """
        if schema is not None:
            fmt = {"type": "json_schema", "json_schema": {"name": "answer", "strict": True, "schema": schema}}
            try:
                return self._json_turn(messages, temperature, fmt)
            except urllib.error.HTTPError as exc:
                if not 400 <= exc.code < 500:
                    raise ConnectionError(f"model endpoint {self.base_url} answered HTTP {exc.code}") from exc
        try:
            return self._json_turn(messages, temperature, {"type": "json_object"})
        except urllib.error.HTTPError as exc:
            raise ConnectionError(f"model endpoint {self.base_url} answered HTTP {exc.code}") from exc

    def _json_turn(self, messages: list[dict[str, Any]], temperature: float, fmt: dict[str, Any]) -> str:
        body = json.dumps({"model": self.model, "messages": messages, "temperature": temperature, "response_format": fmt}).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"model endpoint {self.base_url} unreachable: {exc}") from exc
        return parse_chat_response(data).content


def parse_chat_response(data: dict[str, Any]) -> AssistantMessage:
    try:
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("unexpected response shape from model endpoint") from exc
    calls: list[ToolCall] = []
    for i, c in enumerate(msg.get("tool_calls") or []):
        fn = c.get("function", {})
        raw = fn.get("arguments", "{}")
        if isinstance(raw, dict):
            args = raw
        else:
            try:
                args = json.loads(raw or "{}")
                if not isinstance(args, dict):
                    args = {"_invalid": raw}
            except json.JSONDecodeError:
                args = {"_invalid": raw}
        calls.append(ToolCall(c.get("id") or f"call_{i}", fn.get("name", ""), args))
    return AssistantMessage(msg.get("content") or "", calls)


AGENT_PROTOCOL = "threatsight-agent/1"


class AgentHTTPModel:
    """Your own agent behind an HTTP endpoint, tested as a black box.

    Each turn ThreatSight POSTs ``{"protocol": "threatsight-agent/1", "session": ..., "messages": [...],
    "tools": [...]}`` (OpenAI chat format) to the agent's URL. The agent runs its own prompt, framework
    and guardrails and answers ``{"content": "...", "tool_calls": [{"id": ..., "name": ..., "arguments": {...}}]}``,
    or a plain OpenAI chat-completions response. Tool calls act only on the synthetic Nordvik world,
    and the results come back as ``role: tool`` messages on the next turn.
    """

    def __init__(self, url: str, api_key: str | None = None, timeout: float = 180.0, name: str = "agent") -> None:
        self.url = url
        self.api_key = api_key
        self.timeout = timeout
        self.name = f"agent:{name}"
        self.session = uuid.uuid4().hex

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AssistantMessage:
        if not any(m.get("role") == "assistant" for m in messages):
            self.session = uuid.uuid4().hex  # a new conversation starts
        body = json.dumps({"protocol": AGENT_PROTOCOL, "session": self.session, "messages": messages, "tools": tools}).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise ConnectionError(f"agent endpoint answered HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"agent endpoint {self.url} unreachable: {exc}") from exc
        except ValueError as exc:
            raise ValueError("agent endpoint did not answer in JSON") from exc
        return parse_agent_response(data)


def parse_agent_response(data: Any) -> AssistantMessage:
    if not isinstance(data, dict):
        raise ValueError("agent endpoint must answer with a JSON object")
    if "choices" in data:
        return parse_chat_response(data)
    calls: list[ToolCall] = []
    for i, c in enumerate(data.get("tool_calls") or []):
        if not isinstance(c, dict) or not c.get("name"):
            continue
        args = c.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args or "{}")
            except json.JSONDecodeError:
                args = {"_invalid": args}
        calls.append(ToolCall(str(c.get("id") or f"call_{i}"), str(c["name"]), args if isinstance(args, dict) else {"_invalid": args}))
    return AssistantMessage(str(data.get("content") or ""), calls)
