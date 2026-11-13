from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Protocol

from threatsight_api.assurance.catalog import AdapterRequest, AdapterResponse, ToolObservation
from threatsight_api.assurance.simulator import InProcessOrderSupport


class TargetAdapter(Protocol):
    name: str

    def invoke(self, request: AdapterRequest) -> AdapterResponse: ...

    def configure(self, authorization_mode: str) -> dict: ...

    def reset(self, authorization_mode: str | None = None) -> dict: ...

    def state(self) -> dict: ...


class InProcessAdapter:
    name = "inprocess"

    def __init__(self) -> None:
        self.agent = InProcessOrderSupport(mode="open")

    def invoke(self, request: AdapterRequest) -> AdapterResponse:
        raw = self.agent.turn(
            scenario=request.scenario.agent_scenario,
            actor=request.scenario.actor,
            order_id=request.scenario.order_id,
            prompt=request.scenario.prompt,
        )
        return _to_response(raw)

    def configure(self, authorization_mode: str) -> dict:
        return self.agent.set_mode(authorization_mode)  # type: ignore[arg-type]

    def reset(self, authorization_mode: str | None = None) -> dict:
        return self.agent.reset(authorization_mode)  # type: ignore[arg-type]

    def state(self) -> dict:
        return self.agent.snapshot()


class HttpDemoAgentAdapter:
    name = "http_demo_agent"

    def __init__(self, base_url: str, timeout_s: float = 8) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s

    def invoke(self, request: AdapterRequest) -> AdapterResponse:
        payload = {
            "scenario": request.scenario.agent_scenario,
            "actor": request.scenario.actor,
            "order_id": request.scenario.order_id,
            "prompt": request.scenario.prompt,
        }
        raw = self._json("POST", "/v1/turn", payload)
        return _to_response(raw)

    def configure(self, authorization_mode: str) -> dict:
        return self._json("POST", "/v1/config", {"authorization_mode": authorization_mode})

    def reset(self, authorization_mode: str | None = None) -> dict:
        body = {"authorization_mode": authorization_mode} if authorization_mode else {}
        return self._json("POST", "/v1/reset", body or None)

    def state(self) -> dict:
        return self._json("GET", "/v1/state", None)

    def _json(self, method: str, path: str, body: dict | None) -> dict:
        data = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"} if data else {}
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                return json.loads(response.read().decode())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError("Demo agent adapter request failed") from exc


def _to_response(raw: dict) -> AdapterResponse:
    observations = [ToolObservation.model_validate(item) for item in raw.get("observations") or []]
    return AdapterResponse(
        narration=str(raw.get("narration") or ""),
        agent_version=str(raw.get("agent_version") or "unknown"),
        configuration=dict(raw.get("configuration") or {}),
        observations=observations,
        synthetic=bool(raw.get("synthetic", True)),
    )


_INPROCESS: InProcessAdapter | None = None


def build_adapter(kind: str, base_url: str) -> TargetAdapter:
    global _INPROCESS
    if kind == "inprocess":
        if _INPROCESS is None:
            _INPROCESS = InProcessAdapter()
        return _INPROCESS
    if kind == "http":
        return HttpDemoAgentAdapter(base_url)
    raise ValueError(f"Unknown assurance adapter: {kind}")
