"""Write assessment runs as an Inspect AI evaluation log, so `inspect view` can open them.

Inspect AI (UK AI Security Institute) stores an evaluation as one log: the task, the model, a
list of samples (each with its messages, output and scores) and the aggregate results. This module
writes the plain-JSON form of that log (``version: 2``). It needs no Inspect install; the tests check
the output with ``inspect_ai.log.read_eval_log`` when Inspect is available.

How a ThreatSight run maps onto it:

- one **sample** per judged assessment (a retest gives two: without and with the policy);
- the sample's **messages** are the agent's system prompt, the hostile input, every assistant turn
  with its tool calls, and each tool result (including the gateway's decision);
- one **score** per sample from the ``threatsight_judge`` scorer: ``C`` for PASS, ``I`` for FAIL and
  ``N`` for INCONCLUSIVE, with the reason code and summary. The judge reads tool attempts and
  effects only, never the agent's words, and that is stated in the scorer's metadata;
- the **results** carry pass, fail and inconclusive rates and ``accuracy`` (the pass rate), so
  Inspect's log list shows a headline number;
- every sample and the log itself carry ``synthetic: true`` and the evidence-chain head.

A log has a single ``eval.model``. When the runs used several models it is ``threatsight/mixed``
and each sample's output names its real model.
"""
from __future__ import annotations

import json
import time
from importlib import metadata
from typing import Any

from threatsight_world.scenarios import SCENARIOS

TASK = "threatsight/agent-assessment"
SCORER = "threatsight_judge"
SCORE_VALUE = {"PASS": "C", "FAIL": "I", "INCONCLUSIVE": "N"}
NOTICE = "Synthetic demo data from ThreatSight's fictional organisations. No real people, systems or payments."


def _version() -> str:
    try:
        return metadata.version("threatsight-world")
    except metadata.PackageNotFoundError:
        return "0.2.0"


def _iso(created: str | None) -> str:
    """ThreatSight writes 2026-11-08T12:03:27Z; Inspect expects an offset."""
    if not created:
        return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    return created[:-1] + "+00:00" if created.endswith("Z") else created


def _model(name: str) -> str:
    """Inspect names models provider/model. Keep a name that already has a slash."""
    return name if "/" in name else f"threatsight/{name}"


def _text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def _messages(sc: Any, transcript: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if sc is not None:
        out.append({"role": "system", "content": sc.system_prompt, "source": "input"})
    pending: list[dict[str, Any]] = []  # tool calls from the last assistant turn, matched to results in order
    n = 0
    for e in transcript:
        kind = e.get("type")
        if kind == "input":
            out.append({"role": "user", "content": e.get("text", ""), "source": "input"})
        elif kind == "assistant":
            calls = []
            for c in e.get("tool_calls") or []:
                n += 1
                calls.append({"id": c.get("id") or f"call_{n}", "function": c.get("name", ""), "arguments": c.get("arguments") or {}, "type": "function"})
            pending = list(calls)
            msg: dict[str, Any] = {"role": "assistant", "content": e.get("content") or "", "source": "generate"}
            if calls:
                msg["tool_calls"] = calls
            out.append(msg)
        elif kind == "tool":
            match = next((c for c in pending if c["function"] == e.get("name")), None)
            if match is not None:
                pending.remove(match)
            else:
                n += 1
            decision = e.get("decision") or {}
            msg = {"role": "tool", "content": _text(e.get("result")), "tool_call_id": match["id"] if match else f"call_{n}",
                   "function": e.get("name", ""),
                   "metadata": {"gateway": decision, "executed": bool(e.get("executed"))}}
            if not e.get("executed"):
                msg["error"] = {"type": "approval" if decision.get("hold") else "permission",
                                "message": decision.get("reason") or "blocked by the policy gateway"}
            out.append(msg)
    return out


def _sample(record: dict[str, Any], index: int, a: dict[str, Any]) -> dict[str, Any]:
    sc = SCENARIOS.get(record.get("scenario", ""))
    verdict = a.get("verdict") or {}
    # A held call decided later by a named person: the decision's verdict is the outcome (a FAIL wins).
    decided = [d for d in record.get("approvals") or [] if d.get("run") == index - 1]
    held = verdict if decided else None
    for d in decided:
        if verdict is held or d["verdict"]["verdict"] == "FAIL":
            verdict = d["verdict"]
    messages = _messages(sc, a.get("transcript") or [])
    last = next((m for m in reversed(messages) if m["role"] == "assistant"), {"role": "assistant", "content": "", "source": "generate"})
    tags = {"owasp_llm": list(sc.control.tags), "owasp_agentic": list(sc.control.agentic), "mitre_atlas": list(sc.control.atlas)} if sc else {}
    user = next((m["content"] for m in messages if m["role"] == "user"), "")
    created = _iso(record.get("created"))
    return {
        "id": f"{record['id']}/{index}",
        "epoch": 1,
        "input": user,
        "target": sc.control.title if sc else (record.get("control") or ""),
        "messages": messages,
        "output": {"model": _model(a.get("model", "unknown")),
                   "choices": [{"message": last, "stop_reason": "tool_calls" if last.get("tool_calls") else "stop"}],
                   "completion": last.get("content") or ""},
        "scores": {SCORER: {"value": SCORE_VALUE.get(verdict.get("verdict"), "N"), "answer": verdict.get("verdict"),
                            "explanation": verdict.get("summary"),
                            "metadata": {"reason_code": verdict.get("reason_code"), "evaluator": verdict.get("evaluator")}}},
        "metadata": {
            "synthetic": True, "run_id": record["id"], "profile": record.get("profile"), "organisation": record.get("organisation"),
            "scenario": record.get("scenario"), "title": record.get("title"), "agent": record.get("agent"),
            "control": record.get("control"), "mode": record.get("mode"), "step": "without policy" if index == 1 and len(record.get("runs", [])) > 1 else "with policy" if index > 1 else "run",
            "model": a.get("model"), "policy": a.get("policy"), "verdict": verdict.get("verdict"), "reason_code": verdict.get("reason_code"),
            "tool_calls": a.get("tool_calls") or [], "effects": a.get("effects") or [], **tags,
            **({"verdict_before_approval": held, "approvals": decided} if decided else {}),
            "evidence_head": (record.get("evidence") or {}).get("head"), "evidence_valid": (record.get("evidence") or {}).get("valid"),
            **({"utility": record["utility"]} if index == len(record.get("runs", [])) and record.get("utility") else {}),
        },
        "store": {},
        "events": [],
        "model_usage": {},
        "started_at": created,
        "completed_at": created,
        "attachments": {},
    }


def eval_log(records: list[dict[str, Any]], name: str = "ThreatSight agent assessments") -> dict[str, Any]:
    """One Inspect evaluation log (as a dict) holding every assessment in ``records``."""
    samples = [_sample(r, i, a) for r in records for i, a in enumerate(r.get("runs") or [], 1)]
    models = sorted({s["output"]["model"] for s in samples})
    model = models[0] if len(models) == 1 else "threatsight/mixed"
    created = sorted(_iso(r.get("created")) for r in records) or [_iso(None)]
    verdicts = [s["scores"][SCORER]["answer"] for s in samples]
    total = len(samples)

    def rate(v: str) -> float:
        return round(verdicts.count(v) / total, 4) if total else 0.0

    metrics = {"accuracy": rate("PASS"), "pass_rate": rate("PASS"), "fail_rate": rate("FAIL"), "inconclusive_rate": rate("INCONCLUSIVE")}
    profiles = sorted({r.get("profile") or "nordvik" for r in records})
    policies = sorted({s["metadata"]["policy"] for s in samples if s["metadata"]["policy"]})
    run_id = records[0]["id"] if len(records) == 1 else f"threatsight-{created[-1][:19].replace(':', '')}"
    return {
        "version": 2,
        "status": "success",
        "eval": {
            "run_id": run_id,
            "eval_id": run_id,
            "created": created[0],
            "task": TASK,
            "task_id": "threatsight-world",
            "task_version": 0,
            "task_display_name": name,
            "task_attribs": {},
            "task_args": {},
            "dataset": {"name": "threatsight-world/" + "+".join(profiles), "samples": total, "sample_ids": [s["id"] for s in samples], "shuffled": False},
            "model": model,
            "model_args": {},
            "config": {},
            "packages": {"threatsight-world": _version()},
            "metadata": {"synthetic": True, "notice": NOTICE, "source": "ThreatSight", "models": models, "policies": policies,
                         "runs": [r["id"] for r in records]},
        },
        "plan": {"name": "plan", "steps": [{"solver": "threatsight_agent", "params": {"policies": policies}}], "config": {}},
        "results": {
            "total_samples": total,
            "completed_samples": total,
            "scores": [{"name": SCORER, "scorer": SCORER, "params": {}, "scored_samples": total, "unscored_samples": 0,
                        "metrics": {k: {"name": k, "value": v, "params": {}} for k, v in metrics.items()},
                        "metadata": {"judge": "deterministic: reads tool attempts and effects only, never the agent's words",
                                     "values": {"C": "PASS", "I": "FAIL", "N": "INCONCLUSIVE"}}}],
        },
        "stats": {"started_at": created[0], "completed_at": created[-1], "model_usage": {}},
        "samples": samples,
    }


def run_records(runs_dir: Any, limit: int = 1000) -> list[dict[str, Any]]:
    """Stored run records, newest first, as the server writes them (skips anything unreadable)."""
    if not runs_dir.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(runs_dir.glob("*.json"), reverse=True):
        if len(out) >= limit:
            break
        try:
            r = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(r, dict) and r.get("synthetic") and r.get("runs") and r.get("id"):
            out.append(r)
    return out


def filename(log: dict[str, Any]) -> str:
    """Inspect's own naming, <created>_<task>_<id>.json, so `inspect view` lists it like any other log."""
    stamp = log["eval"]["created"][:19].replace(":", "-") + "+00-00"
    return f"{stamp}_threatsight-agent-assessment_{log['eval']['run_id']}.json"
