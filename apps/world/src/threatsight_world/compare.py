"""Compare models: every attack scenario against every chosen model, without and with the policy.

A comparison can take minutes on a local GPU, so it runs as a background job. Jobs run one at a
time (one GPU), each cell is saved as soon as it finishes so the page can show progress, and every
step goes into one hash-chained evidence file per comparison. Verdicts are the same deterministic
judge as single runs: the model's words never decide a cell.
"""
from __future__ import annotations

import json
import queue
import re
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from threatsight_world import evidence as ev
from threatsight_world.assess import Provider, run_assessment, run_utility
from threatsight_world.policy import Gateway
from threatsight_world import profiles
from threatsight_world.scenarios import SCENARIOS, scenarios_for

JOB_ID = re.compile(r"^cmp-[0-9]{8}T[0-9]{6}-[0-9a-f]{6}$")
MAX_MODELS = 6


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _said(events: list[dict[str, Any]]) -> str:
    text = " ".join(str(e.get("content") or "") for e in events if e.get("type") == "assistant").strip()
    return text[:280]


class Comparisons:
    def __init__(self, runs_dir: Path, provider_for: Callable[[str], Provider], label_for: Callable[[str], str], evidence_key: str | None,
                 on_done: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.dir = runs_dir / "compare"
        self.on_done = on_done
        self.provider_for = provider_for
        self.label_for = label_for
        self.evidence_key = evidence_key
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()
        self._worker: threading.Thread | None = None

    # Storage --------------------------------------------------------------------------------

    def _path(self, job_id: str) -> Path:
        return self.dir / f"{job_id}.json"

    def get(self, job_id: str) -> dict[str, Any] | None:
        if not JOB_ID.match(job_id):
            return None
        p = self._path(job_id)
        try:
            return json.loads(p.read_text()) if p.is_file() else None
        except (OSError, ValueError):
            return None

    def _write(self, job: dict[str, Any]) -> None:
        with self._lock:
            self.dir.mkdir(parents=True, exist_ok=True)
            tmp = self._path(job["id"]).with_suffix(".tmp")
            tmp.write_text(json.dumps(job, indent=2, sort_keys=True))
            tmp.replace(self._path(job["id"]))

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self.dir.is_dir():
            return []
        out = []
        for p in sorted(self.dir.glob("cmp-*.json"), reverse=True)[:limit]:
            try:
                j = json.loads(p.read_text())
            except (OSError, ValueError):
                continue
            out.append({k: j.get(k) for k in ("id", "created", "status", "models", "done", "total")} | {"profile": j.get("profile", "nordvik")})
        return out

    def recover(self) -> None:
        """After a restart, comparisons that were queued or running will never finish: say so."""
        if not self.dir.is_dir():
            return
        for p in self.dir.glob("cmp-*.json"):
            job = self.get(p.stem)
            if job and job.get("status") in {"queued", "running"}:
                job |= {"status": "interrupted", "finished": _now(), "summary": summarise(job)}
                self._write(job)

    # Jobs -----------------------------------------------------------------------------------

    def start(self, body: dict[str, Any], available: list[str]) -> dict[str, Any]:
        models = body.get("models")
        if not isinstance(models, list) or not models or not all(isinstance(m, str) for m in models):
            raise ValueError("pick at least one model to compare")
        models = list(dict.fromkeys(models))
        if len(models) > MAX_MODELS:
            raise ValueError(f"compare at most {MAX_MODELS} models at a time")
        unknown = [m for m in models if m not in available]
        if unknown:
            raise ValueError(f"unknown model {unknown[0]!r}")
        profile = profiles.get(body.get("profile"))
        scenarios = [sc.id for sc in scenarios_for(profile.id)]
        job_id = time.strftime("cmp-%Y%m%dT%H%M%S-", time.gmtime()) + uuid.uuid4().hex[:6]
        job = {
            "id": job_id,
            "created": _now(),
            "status": "queued",
            "profile": profile.id,
            "organisation": profile.organisation,
            "policy": profile.policy,
            "models": [{"id": m, "label": self.label_for(m)} for m in models],
            "scenarios": [{"id": s, "agent": SCENARIOS[s].agent, "title": SCENARIOS[s].title, "control": SCENARIOS[s].control.id} for s in scenarios],
            "cells": {},
            "done": 0,
            "total": len(models) * len(scenarios),
        }
        self._write(job)
        self._queue.put(job_id)
        self._ensure_worker()
        return job

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._drain, name="compare-worker", daemon=True)
                self._worker.start()

    def _drain(self) -> None:
        while True:
            try:
                job_id = self._queue.get(timeout=1)
            except queue.Empty:
                return
            try:
                self.run(job_id)
            except Exception as exc:  # noqa: BLE001 - keep the worker alive and say what went wrong
                job = self.get(job_id)
                if job is not None:
                    job |= {"status": "failed", "error": str(exc)[:300], "finished": _now()}
                    self._write(job)
            finally:
                self._queue.task_done()

    def run(self, job_id: str) -> dict[str, Any]:
        job = self.get(job_id)
        assert job is not None
        job["status"], job["started"] = "running", _now()
        self._write(job)
        log = ev.EvidenceLog(key=self.evidence_key)
        log.append("comparison_started", {"id": job_id, "models": [m["id"] for m in job["models"]], "policy": job["policy"]})
        hardened = Gateway.from_name(job["policy"])
        for m in job["models"]:
            for s in job["scenarios"]:
                job["cells"][f"{s['id']}|{m['id']}"] = self._cell(SCENARIOS[s["id"]], m["id"], hardened, log)
                job["done"] += 1
                self._write(job)
        ok, _, msg = log.verify()
        self.dir.mkdir(parents=True, exist_ok=True)
        log.write(self.dir / f"{job_id}.evidence.jsonl")
        job |= {"status": "done", "finished": _now(), "summary": summarise(job),
                "evidence": {"records": len(log.records), "head": log.last_hash, "signed": bool(log.key), "valid": ok, "message": msg}}
        self._write(job)
        if self.on_done:
            self.on_done(job)
        return job

    def _cell(self, sc: Any, model_id: str, hardened: Gateway, log: ev.EvidenceLog) -> dict[str, Any]:
        started = time.monotonic()
        try:
            provider = self.provider_for(model_id)
            before = run_assessment(sc, provider, Gateway(None), log)
            after = run_assessment(sc, provider, hardened, log)
            utility = run_utility(sc, provider, hardened)
            log.append("utility", {"scenario": sc.id, "model": model_id, "tasks": utility})
        except (ConnectionError, ValueError) as exc:
            log.append("cell_error", {"scenario": sc.id, "model": model_id, "error": str(exc)[:300]})
            return {"error": str(exc)[:300], "ms": round((time.monotonic() - started) * 1000)}
        return {
            "before": {**before.verdict.to_dict(), "calls": [t.name for t in before.trace.attempts], "said": _said(before.trace.events)},
            "after": {**after.verdict.to_dict(), "calls": [t.name for t in after.trace.attempts], "said": _said(after.trace.events)},
            "utility": {"passed": sum(1 for u in utility if u["passed"]), "total": len(utility)},
            "ms": round((time.monotonic() - started) * 1000),
        }


def summarise(job: dict[str, Any]) -> list[dict[str, Any]]:
    """Per model: how many attacks did harm without the policy, how many with it, and normal work kept."""
    out = []
    for m in job["models"]:
        cells = [job["cells"].get(f"{s['id']}|{m['id']}", {}) for s in job["scenarios"]]
        ok = [c for c in cells if "before" in c]
        out.append({
            "model": m["id"],
            "label": m["label"],
            "harm_before": sum(1 for c in ok if c["before"]["verdict"] == "FAIL"),
            "harm_after": sum(1 for c in ok if c["after"]["verdict"] == "FAIL"),
            "work_passed": sum(c["utility"]["passed"] for c in ok),
            "work_total": sum(c["utility"]["total"] for c in ok),
            "errors": len(cells) - len(ok),
            "scenarios": len(cells),
        })
    return out
