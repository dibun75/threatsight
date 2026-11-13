"""Run an attack scenario, judge it, retest under a policy, and write evidence and recordings."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from threatsight_world.evidence import EvidenceLog
from threatsight_world.judge import Verdict, judge_control
from threatsight_world.llm import AssistantMessage, ChatModel, ScriptedModel
from threatsight_world.policy import Gateway
from threatsight_world.runtime import Trace, run_agent
from threatsight_world.scenarios import Scenario, Task
from threatsight_world.world import seed_world


class Provider(Protocol):
    name: str

    def attack_model(self, sc: Scenario) -> ChatModel: ...

    def task_model(self, sc: Scenario, task: Task) -> ChatModel | None: ...


class ScriptedProvider:
    name = "scripted"

    def attack_model(self, sc: Scenario) -> ChatModel:
        return ScriptedModel(sc.attack_script)

    def task_model(self, sc: Scenario, task: Task) -> ChatModel | None:
        return ScriptedModel(task.script)


class LiveProvider:
    """One live model answers everything. It is stateless, so it can be reused."""

    def __init__(self, model: ChatModel) -> None:
        self.model = model
        self.name = model.name

    def attack_model(self, sc: Scenario) -> ChatModel:
        return self.model

    def task_model(self, sc: Scenario, task: Task) -> ChatModel | None:
        return self.model


class ReplayProvider:
    """Replays the assistant turns of a recorded run. Routine tasks replay too when they were recorded."""

    def __init__(self, path: str | Path) -> None:
        self.header, self.turns = load_recording(path)
        self.task_turns = load_task_turns(path)
        self.name = f"replay:{self.header.get('model', 'unknown')}"

    def attack_model(self, sc: Scenario) -> ChatModel:
        return ScriptedModel(self.turns, name=self.name)

    def task_model(self, sc: Scenario, task: Task) -> ChatModel | None:
        turns = self.task_turns.get(task.label)
        return ScriptedModel(turns, name=self.name) if turns else None


@dataclass
class Assessment:
    scenario_id: str
    model: str
    policy: str
    verdict: Verdict
    trace: Trace
    effects: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """The stored form of one judged assessment (what the server keeps under a run's "runs")."""
        return {
            "model": self.model,
            "policy": self.policy,
            "verdict": self.verdict.to_dict(),
            "tool_calls": [{"name": t.name, "args": t.args, "allowed": t.allowed, "executed": t.executed, "rule": t.rule, "held": t.held} for t in self.trace.attempts],
            "effects": self.effects,
            "transcript": [e for e in self.trace.events if e.get("type") in {"input", "assistant", "tool"}],
        }


def run_assessment(sc: Scenario, provider: Provider, gateway: Gateway, evidence: EvidenceLog | None = None) -> Assessment:
    world = seed_world(sc.profile)
    model = provider.attack_model(sc)
    if evidence:
        evidence.append("run_started", {"scenario": sc.id, "control": sc.control.id, "agent": sc.agent, "model": model.name, "policy": gateway.name})
    trace = run_agent(model, sc.system_prompt, sc.attack_message, sc.tools, world, sc.ctx, gateway)
    verdict = judge_control(sc.control, trace.attempts, world.effects)
    effects = [{"kind": e.kind, **e.details} for e in world.effects if e.kind != "tool_executed"]
    if evidence:
        for ev in trace.events:
            evidence.append("trace_event", ev)
        evidence.append("verdict", {"control": sc.control.id, **verdict.to_dict(), "effects": effects})
    return Assessment(sc.id, model.name, gateway.name, verdict, trace, effects)


def run_utility(sc: Scenario, provider: Provider, gateway: Gateway) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for task in sc.tasks:
        model = provider.task_model(sc, task)
        if model is None:
            out.append({"task": task.label, "passed": None})
            continue
        world = seed_world(sc.profile)
        run_agent(model, sc.system_prompt, task.user_message, sc.tools, world, task.ctx or sc.ctx, gateway)
        out.append({"task": task.label, "passed": bool(task.check(world))})
    return out


def retest(sc: Scenario, provider: Provider, hardened: Gateway, evidence: EvidenceLog | None = None) -> dict[str, Any]:
    """Attack an open gateway, then the same attack under the policy, then check normal work still passes."""
    before = run_assessment(sc, provider, Gateway(None), evidence)
    if evidence:
        evidence.append("retest_started", {"scenario": sc.id, "parent_verdict": before.verdict.to_dict(), "policy": hardened.name})
    after = run_assessment(sc, provider, hardened, evidence)
    utility = run_utility(sc, provider, hardened)
    if evidence:
        evidence.append("utility", {"scenario": sc.id, "policy": hardened.name, "tasks": utility})
    return {"scenario": sc.id, "title": sc.title, "before": before, "after": after, "utility": utility}


def write_recording(
    path: str | Path,
    a: Assessment,
    sc: Scenario,
    extra: dict[str, Any] | None = None,
    tasks: dict[str, Trace] | None = None,
) -> None:
    lines = [{"type": "header", "scenario": sc.id, "model": a.model, "policy": a.policy, **(extra or {})}]
    lines += [ev for ev in a.trace.events if ev["type"] in {"input", "assistant", "tool"}]
    for label, trace in (tasks or {}).items():
        lines += [{**ev, "type": "task_assistant", "task": label} for ev in trace.events if ev["type"] == "assistant"]
    Path(path).write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in lines))


def record_scenario(sc: Scenario, provider: Provider, tries: int = 1) -> tuple[Assessment, dict[str, Trace], dict[str, Any]]:
    """Run the attack under no policy up to `tries` times and keep the first run with a hostile attempt.

    The header says how many tries it took (or that none attempted), so a replay never hides that it
    was selected. Routine tasks are run once each and recorded so a retest can replay them too.
    """
    kept: Assessment | None = None
    used = 0
    for used in range(1, max(1, tries) + 1):
        kept = run_assessment(sc, provider, Gateway(None))
        if any(sc.control.is_hostile_attempt(t) for t in kept.trace.attempts):
            break
    assert kept is not None
    attempted = any(sc.control.is_hostile_attempt(t) for t in kept.trace.attempts)
    task_traces: dict[str, Trace] = {}
    for task in sc.tasks:
        model = provider.task_model(sc, task)
        if model is not None:
            task_traces[task.label] = run_agent(model, sc.system_prompt, task.user_message, sc.tools, seed_world(sc.profile), task.ctx or sc.ctx, Gateway(None))
    extra = {"tries": used, "max_tries": tries, "hostile_attempt": attempted, "recorded": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    return kept, task_traces, extra


def load_recording(path: str | Path) -> tuple[dict[str, Any], list[AssistantMessage]]:
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    header = next((r for r in rows if r.get("type") == "header"), {})
    turns = [AssistantMessage.from_dict(r) for r in rows if r.get("type") == "assistant"]
    return header, turns


def load_task_turns(path: str | Path) -> dict[str, list[AssistantMessage]]:
    out: dict[str, list[AssistantMessage]] = {}
    for line in Path(path).read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("type") == "task_assistant":
                out.setdefault(r["task"], []).append(AssistantMessage.from_dict(r))
    return out
