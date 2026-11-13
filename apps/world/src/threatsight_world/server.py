"""Small HTTP API over the synthetic demo worlds (Nordvik Municipality and Helio Cloud), for the web UI.

Everything this server returns is fictional demo data. It has no database connection and never
talks to the ThreatSight API or its Postgres: each run starts from a freshly seeded in-memory
world, and results go only to the runs directory as JSON plus a hash-chained evidence file.
Every response carries ``"synthetic": true`` so the UI can label it.

The model is chosen by the operator, never by the request: ``scripted`` by default, a local
OpenAI-compatible endpoint when ``THREATSIGHT_LLM_MODEL`` is set (base URL from
``THREATSIGHT_LLM_BASE_URL``) or saved on the Settings page (see ``settings.py``), and ``replay`` for scenarios that have a recording in
``THREATSIGHT_WORLD_RECORDINGS`` (made with ``threatsight-world record``). Clients cannot point the
server at other URLs or files.

    python -m threatsight_world.server --port 8092
"""
from __future__ import annotations

import argparse
import json
import os
import re
import threading
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from threatsight_world import evidence as ev
from threatsight_world import profiles
from threatsight_world.assess import Assessment, LiveProvider, Provider, ReplayProvider, ScriptedProvider, load_recording, retest, run_assessment
from threatsight_world.compare import Comparisons
from threatsight_world.connections import ENDPOINT_ID, Connections, check
from threatsight_world.settings import ModelSettings, env_defaults, probe
from threatsight_world.exports import CELL_COLUMNS, RUN_COLUMNS, cell_rows, run_rows, to_csv
from threatsight_world.inspect_log import eval_log, filename as inspect_filename, run_records
from threatsight_world.integrations import DEST_ID, Integrations, comparison_event, run_events
from threatsight_world.graph import build_graph
from threatsight_world.judge import judge_control
from threatsight_world.tools import TOOLS, Context
from threatsight_world.world import seed_world
from threatsight_world.policy import Gateway, PolicyError
from threatsight_world import remediate as rem
from threatsight_world.scenarios import SCENARIOS, scenarios_for

DATA_LABEL = {
    "synthetic": True,
    "organisation": "Nordvik Municipality (fictional)",
    "notice": "Synthetic demo data. No real people, systems or payments. Not stored in the ThreatSight database.",
}
POLICIES = ("open", *(p.policy for p in profiles.PROFILES.values()))
CUSTOM = "custom"


def label_for(profile: str) -> dict[str, Any]:
    return {**DATA_LABEL, "organisation": profiles.get(profile).organisation}


def _hardened_rules(profile: str = profiles.DEFAULT) -> list[dict[str, Any]]:
    return Gateway.from_name(profiles.get(profile).policy).rules


def guardable_tools(profile: str = profiles.DEFAULT) -> list[str]:
    """Tools the viewer may put under the policy: only those the profile's reviewed policy has rules for."""
    return sorted({r["tool"] for r in _hardened_rules(profile)})


def gateway_for(policy: str, guard: Any = None, profile: str = profiles.DEFAULT) -> Gateway:
    """open, the profile's hardened policy, or custom: those rules for just the tools the viewer picked.

    The client never sends rules, only tool names, so every rule that can run is one already in the
    reviewed policy file. Another profile's policy is refused: its rules are about other systems.
    """
    if policy == "open":
        return Gateway(None)
    if policy in POLICIES:
        if policy != profiles.get(profile).policy:
            raise ValueError(f"{policy} is for another organisation; use {profiles.get(profile).policy}")
        return Gateway.from_name(policy)
    if policy != CUSTOM:
        raise ValueError(f"policy must be one of {[*POLICIES, CUSTOM]}")
    if isinstance(guard, str):
        guard = [g for g in guard.split(",") if g]
    if not isinstance(guard, list) or not all(isinstance(g, str) for g in guard):
        raise ValueError("guard must be a list of tool names")
    allowed = set(guardable_tools(profile))
    unknown = sorted(set(guard) - allowed)
    if unknown:
        raise ValueError(f"cannot guard {unknown}; guardable tools are {sorted(allowed)}")
    chosen = sorted(set(guard))
    if not chosen:
        return Gateway(None)
    return Gateway({"name": f"{CUSTOM}:{','.join(chosen)}", "rules": [r for r in _hardened_rules(profile) if r["tool"] in chosen]})
RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}-[0-9a-f]{8}$")
MAX_APPROVER = 80
MAX_BODY = 4096


class Config:
    def __init__(self, runs_dir: Path, llm_base: str, llm_model: str | None, llm_key: str | None, recordings: Path | None = None,
                 public_url: str | None = None, proposer: str | None = None) -> None:
        self.runs_dir = runs_dir
        self.public_url = public_url
        self.recordings = recordings
        self.lock = threading.Lock()
        # The environment (or the arguments here) are defaults; the Settings page saves overrides.
        self.settings = ModelSettings(runs_dir, {"local_base": llm_base, "local_model": llm_model, "local_key": llm_key,
                                                 "agent": None, "proposer": proposer})
        self.connections = Connections(runs_dir, llm_base, llm_model, llm_key)
        self.apply_settings()
        self.integrations = Integrations(runs_dir, public_url)
        self.compare = Comparisons(runs_dir, self.compare_provider, self.label, os.environ.get("THREATSIGHT_EVIDENCE_KEY") or None,
                                   on_done=lambda job: self.integrations.emit(comparison_event(job, self.public_url)))

    @classmethod
    def from_env(cls) -> Config:
        env = env_defaults()
        return cls(
            Path(os.environ.get("THREATSIGHT_WORLD_RUNS_DIR", "runs")),
            str(env["local_base"]),
            env["local_model"],
            env["local_key"],
            Path(os.environ["THREATSIGHT_WORLD_RECORDINGS"]) if os.environ.get("THREATSIGHT_WORLD_RECORDINGS") else None,
            os.environ.get("THREATSIGHT_PUBLIC_URL") or None,
            env["proposer"],
        )

    def apply_settings(self) -> None:
        eff = self.settings.effective()
        self.llm_base = str(eff["local_base"]).rstrip("/")
        self.llm_model = eff["local_model"]
        self.llm_key = eff["local_key"]
        self.connections.configure(self.llm_base, self.llm_model, self.llm_key)

    def update_settings(self, body: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            self.settings.update(body)
            self.apply_settings()
        return self.settings_view()

    def _known(self, connection_id: str | None) -> str | None:
        """The connection id if it still exists. A local model counts while it is the default or is listed."""
        if not connection_id:
            return None
        if connection_id.startswith("local:"):
            return connection_id if self.llm_model else None
        return connection_id if any(e.id == connection_id for e in self.connections.endpoints()) else None

    def agent_connection(self) -> str | None:
        """What "live" runs on: the chosen agent model, else the default local model."""
        return self._known(self.settings.effective()["agent"]) or (f"local:{self.llm_model}" if self.llm_model else None)

    def proposer_connection(self) -> str | None:
        """What writes fix proposals: the chosen proposer, else the agent model."""
        return self._known(self.settings.effective()["proposer"]) or self.agent_connection()

    def settings_view(self) -> dict[str, Any]:
        options = self.connections.options()
        return {**DATA_LABEL, **self.settings.view(), "connections": options,
                "effective": {"agent": self.agent_connection(), "proposer": self.proposer_connection()},
                "labels": {"agent": self.label(self.agent_connection()) if self.agent_connection() else None,
                           "proposer": self.label(self.proposer_connection()) if self.proposer_connection() else None}}

    def recording(self, scenario_id: str) -> Path | None:
        if not self.recordings or scenario_id not in SCENARIOS:
            return None
        p = self.recordings / f"{scenario_id}.jsonl"
        return p if p.is_file() else None

    def replay_info(self, scenario_id: str) -> dict[str, Any] | None:
        p = self.recording(scenario_id)
        if not p:
            return None
        header, _ = load_recording(p)
        keys = ("model", "tries", "max_tries", "hostile_attempt", "recorded")
        return {k: header.get(k) for k in keys}

    def live_label(self) -> str | None:
        c = self.agent_connection()
        return self.label(c) if c else None

    def models(self) -> list[str]:
        """scripted, live (the chosen agent model), replay, then every connection by id."""
        has_replay = any(self.recording(s) for s in SCENARIOS)
        live = self.agent_connection()
        base = ["scripted"] + (["live"] if live else []) + (["replay"] if has_replay else [])
        return base + [o["id"] for o in self.connections.options() if o["id"] != live]

    def compare_models(self) -> list[str]:
        return ["scripted"] + [o["id"] for o in self.connections.options()]

    def label(self, model_id: str) -> str:
        if model_id == "scripted":
            return "Scripted baseline"
        return self.connections.label(model_id)

    def compare_provider(self, model_id: str) -> Provider:
        if model_id == "scripted":
            return ScriptedProvider()
        return LiveProvider(self.connections.model(model_id))

    def provider(self, name: str, scenario_id: str) -> Provider:
        if name == "scripted":
            return ScriptedProvider()
        live = self.agent_connection()
        if name == "live" and live:
            return LiveProvider(self.connections.model(live))
        if name in {o["id"] for o in self.connections.options()}:
            return LiveProvider(self.connections.model(name))
        if name == "replay":
            p = self.recording(scenario_id)
            if p:
                return ReplayProvider(p)
            raise ValueError(f"no recording for {scenario_id}")
        raise ValueError(f"model must be one of {self.models()}")


def _assessment(a: Assessment) -> dict[str, Any]:
    return a.to_dict()


def scenario_list(cfg: Config, profile: str | None = None) -> list[dict[str, Any]]:
    return [
        {"id": sc.id, "profile": sc.profile, "title": sc.title, "agent": sc.agent, "control": sc.control.id, "control_title": sc.control.title,
         "tags": list(sc.control.tags), "agentic": list(sc.control.agentic), "atlas": list(sc.control.atlas), "tools": sc.tools, "attack_message": sc.attack_message, "replay": cfg.replay_info(sc.id)}
        for sc in (scenarios_for(profile) if profile else SCENARIOS.values())
    ]


def execute(cfg: Config, body: dict[str, Any]) -> dict[str, Any]:
    """Run one scenario (mode=run) or the open -> policy -> utility sequence (mode=retest)."""
    sc_id = body.get("scenario")
    if sc_id not in SCENARIOS:
        raise ValueError(f"unknown scenario {sc_id!r}")
    sc = SCENARIOS[sc_id]
    mode = body.get("mode", "run")
    policy = body.get("policy", "open")
    gateway = gateway_for(policy, body.get("guard"), sc.profile)
    provider = cfg.provider(body.get("model", "scripted"), sc.id)
    log = ev.EvidenceLog(key=os.environ.get("THREATSIGHT_EVIDENCE_KEY") or None)
    started = time.time()
    if mode == "run":
        a = run_assessment(sc, provider, gateway, log)
        result: dict[str, Any] = {"runs": [_assessment(a)], "verdict": a.verdict.verdict}
    elif mode == "retest":
        hardened = Gateway.from_name(profiles.get(sc.profile).policy) if policy == "open" else gateway
        if not hardened.rules:
            raise ValueError("pick at least one tool to guard before a retest")
        r = retest(sc, provider, hardened, log)
        result = {"runs": [_assessment(r["before"]), _assessment(r["after"])], "utility": r["utility"], "verdict": r["after"].verdict.verdict}
    else:
        raise ValueError("mode must be run or retest")
    ok, _, msg = log.verify()
    run_id = time.strftime("%Y%m%dT%H%M%S", time.gmtime(started)) + "-" + uuid.uuid4().hex[:8]
    record = {
        **label_for(sc.profile),
        "profile": sc.profile,
        "id": run_id,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "duration_ms": round((time.time() - started) * 1000),
        "scenario": sc.id,
        "title": sc.title,
        "agent": sc.agent,
        "control": sc.control.id,
        "mode": mode,
        **result,
        "evidence": {"records": len(log.records), "head": log.last_hash, "signed": bool(log.key), "valid": ok, "message": msg},
    }
    with cfg.lock:
        cfg.runs_dir.mkdir(parents=True, exist_ok=True)
        log.write(cfg.runs_dir / f"{run_id}.evidence.jsonl")
        (cfg.runs_dir / f"{run_id}.json").write_text(json.dumps(record, indent=2, sort_keys=True))
    cfg.integrations.emit(run_events(record, _control(sc.id), cfg.public_url))
    return record


def _control(scenario_id: str) -> dict[str, Any]:
    c = SCENARIOS[scenario_id].control
    return {"title": c.title, "tags": c.tags, "agentic": c.agentic, "atlas": c.atlas}


def list_runs(cfg: Config, limit: int = 50) -> list[dict[str, Any]]:
    if not cfg.runs_dir.is_dir():
        return []
    out = []
    for p in sorted(cfg.runs_dir.glob("*.json"), reverse=True)[:limit]:
        try:
            r = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(r, dict) or not r.get("synthetic") or not r.get("runs"):
            continue  # connections.json and integrations.json live here too
        row = {k: r.get(k) for k in ("id", "created", "scenario", "agent", "control", "mode", "verdict")} | {"profile": r.get("profile", "nordvik")}
        last = r["runs"][-1]
        row |= {"model": last["model"], "policy": last["policy"], "verdicts": [x["verdict"]["verdict"] for x in r["runs"]]}
        out.append(row)
    return out


def get_run(cfg: Config, run_id: str) -> dict[str, Any] | None:
    if not RUN_ID.match(run_id):
        return None
    p = cfg.runs_dir / f"{run_id}.json"
    return json.loads(p.read_text()) if p.is_file() else None


def decide(cfg: Config, run_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    with cfg.lock:  # read-check-write of the run record must not interleave
        return _decide(cfg, run_id, body)


def _decide(cfg: Config, run_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    """A named person approves or rejects a held tool call. Approving runs it in a fresh copy of the
    synthetic world with that person as approver, judges the outcome again, and appends both the
    decision and the result to the run's evidence chain. Each held call can be decided once."""
    record = get_run(cfg, run_id)
    if record is None:
        return None
    run_i, call_i = body.get("run"), body.get("call")
    decision = body.get("decision")
    approver = str(body.get("approver") or "").strip()
    if decision not in {"approve", "reject"}:
        raise ValueError("decision must be approve or reject")
    if not approver or len(approver) > MAX_APPROVER:
        raise ValueError(f"approver name is required (at most {MAX_APPROVER} characters)")
    try:
        call = record["runs"][run_i]["tool_calls"][call_i]
    except (IndexError, KeyError, TypeError):
        raise ValueError("no such tool call") from None
    if not call.get("held"):
        raise ValueError("that tool call is not waiting for approval")
    approvals = record.setdefault("approvals", [])
    if any(a["run"] == run_i and a["call"] == call_i for a in approvals):
        raise ValueError("that tool call has already been decided")
    sc = SCENARIOS[record["scenario"]]
    outcome: dict[str, Any] = {"run": run_i, "call": call_i, "tool": call["name"], "args": call["args"], "decision": decision,
                               "approver": approver, "decided": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if decision == "approve":
        world = seed_world(sc.profile)
        result = TOOLS[call["name"]].fn(world, Context(requester=sc.ctx.requester, approved_by=approver), call["args"])
        effects = [{"kind": e.kind, **e.details} for e in world.effects]
        verdict = judge_control(sc.control, [], world.effects)
        if verdict.verdict == "FAIL":
            verdict_d = {"verdict": "FAIL", "reason_code": "APPROVED_INTO_HARM",
                         "summary": f"{approver} approved the held call and it caused the harm this control exists to prevent ({sc.control.id}). The approver is named in the evidence.", "evaluator": verdict.evaluator}
        else:
            verdict_d = {"verdict": "PASS", "reason_code": "APPROVED_BY_PERSON", "summary": f"{approver} approved the held call; no harm recorded.", "evaluator": verdict.evaluator}
        outcome |= {"result": result, "effects": effects, "verdict": verdict_d}
    else:
        outcome |= {"result": None, "effects": [], "verdict": {"verdict": "PASS", "reason_code": "REJECTED_BY_PERSON",
                                                              "summary": f"{approver} rejected the held call; it never ran.", "evaluator": "deterministic_policy"}}
    log = ev.EvidenceLog(key=os.environ.get("THREATSIGHT_EVIDENCE_KEY") or None)
    evidence_path = cfg.runs_dir / f"{run_id}.evidence.jsonl"
    log.records = ev.load(evidence_path) if evidence_path.is_file() else []
    log.append("approval_decision", outcome)
    log.write(evidence_path)
    ok, _, msg = log.verify()
    approvals.append(outcome)
    was_fail = record.get("verdict") == "FAIL"
    if outcome["verdict"]["verdict"] == "FAIL":
        record["verdict"] = "FAIL"
    record["evidence"] = {**record["evidence"], "records": len(log.records), "head": log.last_hash, "valid": ok, "message": msg}
    (cfg.runs_dir / f"{run_id}.json").write_text(json.dumps(record, indent=2, sort_keys=True))
    if outcome["verdict"]["verdict"] == "FAIL" and not was_fail:
        cfg.integrations.emit(run_events(record, _control(record["scenario"]), cfg.public_url))
    return record


# ---- verified remediation -------------------------------------------------------------------

def _store(cfg: Config, profile: str) -> rem.Store:
    return rem.Store(cfg.runs_dir / "remediation", profiles.get(profile).id)


def remediation_view(cfg: Config, profile: str) -> dict[str, Any]:
    store = _store(cfg, profile)
    return {**label_for(profile), "profile": profile, "live": {"version": store.head(), "policy": store.current()},
            "versions": [{k: v.get(k) for k in ("version", "parent", "created", "by", "proposal", "change", "diff")} for v in store.versions()][::-1],
            "proposals": [{k: p.get(k) for k in ("id", "created", "scenario", "title", "agent", "status", "proposer", "agent_model")} for p in store.proposals()][:50],
            "proposers": ["heuristic"] + (["live"] if cfg.proposer_connection() else []),
            "live_model": cfg.label(cfg.proposer_connection()) if cfg.proposer_connection() else None,
            "disabled": bool(os.environ.get(rem.KILL_SWITCH))}


def remediation_proposer(cfg: Config, name: str) -> Any:
    if name == "heuristic":
        return rem.HeuristicProposer()
    conn = cfg.proposer_connection()
    if name == "live" and conn:
        return rem.ModelProposer(cfg.connections.model(conn))
    raise ValueError("proposer must be heuristic" + (" or live" if conn else ""))


def remediation_post(cfg: Config, parts: list[str], body: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
    """POST /api/world/remediation (propose) and /api/world/remediation/<id>/<apply|reject|rollback>."""
    profile = profiles.get(body.get("profile")).id
    store = _store(cfg, profile)
    with cfg.lock:  # one change to a policy store at a time
        if len(parts) == 3:
            sc_id = body.get("scenario")
            if sc_id not in SCENARIOS or SCENARIOS[sc_id].profile != profile:
                raise ValueError(f"unknown scenario {sc_id!r} for {profile}")
            sc = SCENARIOS[sc_id]
            p = rem.propose(sc, cfg.provider(body.get("model", "scripted"), sc.id), remediation_proposer(cfg, str(body.get("proposer", "heuristic"))), store)
            return 201, p
        pid, action = parts[3], parts[4]
        if store.proposal(pid) is None:
            return 404, None
        approver = str(body.get("approver") or "")
        if action == "apply":
            p = rem.apply(store, pid, approver, cfg.provider(body.get("model", "scripted"), store.proposal(pid)["scenario"]), SCENARIOS)
        elif action == "reject":
            p = rem.reject(store, pid, approver, str(body.get("note") or ""))
        else:
            p = rem.rollback(store, pid, approver)
        return 200, p


def verify_run(cfg: Config, run_id: str) -> dict[str, Any] | None:
    if not RUN_ID.match(run_id):
        return None
    p = cfg.runs_dir / f"{run_id}.evidence.jsonl"
    if not p.is_file():
        return None
    records = ev.load(p)
    ok, index, msg = ev.verify_records(records, key=os.environ.get("THREATSIGHT_EVIDENCE_KEY") or None)
    return {**DATA_LABEL, "id": run_id, "valid": ok, "first_bad_index": index, "message": msg, "records": len(records)}


def make_handler(cfg: Config) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "threatsight-world"

        def log_message(self, fmt: str, *args: Any) -> None:  # one JSON line per request
            print(json.dumps({"path": self.path, "status": args[1] if len(args) > 1 else None}), flush=True)

        def _send(self, status: int, body: Any) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send_text(self, body: str, content_type: str, filename: str) -> None:
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _error(self, status: HTTPStatus, message: str) -> None:
            self._send(status, {**DATA_LABEL, "error": message})

        def do_GET(self) -> None:
            url = urlparse(self.path)
            parts = [p for p in url.path.split("/") if p]
            q = parse_qs(url.query)
            if url.path == "/health":
                return self._send(200, {"status": "ok"})
            if parts[:2] != ["api", "world"]:
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            rest = parts[2:]
            try:
                profile = profiles.get(q.get("profile", [profiles.DEFAULT])[0]).id
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            if rest == ["profiles"]:
                return self._send(200, {**DATA_LABEL, "profiles": [p.public() for p in profiles.PROFILES.values()], "default": profiles.DEFAULT})
            if rest == ["meta"]:
                return self._send(200, {**label_for(profile), "profile": profiles.get(profile).public(), "models": cfg.models(), "live_model": cfg.live_label(),
                                        "policies": ["open", profiles.get(profile).policy], "guardable": guardable_tools(profile),
                                        "connections": cfg.connections.options(), "profiles": [p.public() for p in profiles.PROFILES.values()]})
            if rest == ["settings"]:
                return self._send(200, cfg.settings_view())
            if rest == ["connections"]:
                return self._send(200, {**DATA_LABEL, "connections": cfg.connections.options(), "local_base": cfg.llm_base if cfg.llm_model else None})
            if rest == ["compare"]:
                return self._send(200, {**DATA_LABEL, "comparisons": cfg.compare.list(), "models": [{"id": m, "label": cfg.label(m)} for m in cfg.compare_models()]})
            if len(rest) == 2 and rest[0] == "compare":
                job = cfg.compare.get(rest[1])
                return self._send(200, {**DATA_LABEL, **job}) if job else self._error(HTTPStatus.NOT_FOUND, "comparison not found")
            if rest == ["scenarios"]:
                return self._send(200, {**label_for(profile), "scenarios": scenario_list(cfg, profile if "profile" in q else None)})
            if rest == ["integrations"]:
                return self._send(200, {**DATA_LABEL, **cfg.integrations.view()})
            if len(rest) == 2 and rest[0] == "export":
                try:
                    limit = max(1, min(5000, int(q.get("limit", ["1000"])[0])))
                except ValueError:
                    return self._error(HTTPStatus.BAD_REQUEST, "limit must be a number")
                name = rest[1]
                if name == "runs.inspect.json":
                    records = run_records(cfg.runs_dir, limit)
                    if not records:
                        return self._error(HTTPStatus.NOT_FOUND, "no runs yet")
                    log = eval_log(records)
                    return self._send_text(json.dumps(log, indent=2), "application/json", inspect_filename(log))
                if name in {"runs.json", "runs.csv"}:
                    rows, columns = run_rows(cfg.runs_dir, limit), RUN_COLUMNS
                elif name in {"comparisons.json", "comparisons.csv"}:
                    rows, columns = cell_rows(cfg.runs_dir / "compare", min(limit, 200)), CELL_COLUMNS
                else:
                    return self._error(HTTPStatus.NOT_FOUND, "not found")
                if name.endswith(".csv"):
                    return self._send_text(to_csv(rows, columns), "text/csv; charset=utf-8", f"threatsight-{name}")
                return self._send(200, {**DATA_LABEL, "columns": columns, "rows": rows})
            if rest == ["graph"]:
                try:
                    gateway = gateway_for(q.get("policy", ["open"])[0], q.get("guard", [""])[0], profile)
                except ValueError as exc:
                    return self._error(HTTPStatus.BAD_REQUEST, str(exc))
                return self._send(200, {**label_for(profile), **build_graph(gateway, profile)})
            if rest == ["remediation"]:
                return self._send(200, remediation_view(cfg, profile))
            if len(rest) == 2 and rest[0] == "remediation":
                p = _store(cfg, profile).proposal(rest[1])
                return self._send(200, {**label_for(profile), **p}) if p else self._error(HTTPStatus.NOT_FOUND, "proposal not found")
            if len(rest) == 3 and rest[0] == "remediation" and rest[2] == "evidence.jsonl":
                path = _store(cfg, profile).evidence_path(rest[1])
                if not path:
                    return self._error(HTTPStatus.NOT_FOUND, "proposal not found")
                return self._send_text(path.read_text(), "application/x-ndjson", f"threatsight-{rest[1]}.evidence.jsonl")
            if rest == ["runs"]:
                return self._send(200, {**DATA_LABEL, "runs": list_runs(cfg)})
            if len(rest) == 2 and rest[0] == "runs":
                r = get_run(cfg, rest[1])
                return self._send(200, r) if r else self._error(HTTPStatus.NOT_FOUND, "run not found")
            if len(rest) == 3 and rest[0] == "runs" and rest[2] == "evidence.jsonl" and RUN_ID.match(rest[1]):
                p = cfg.runs_dir / f"{rest[1]}.evidence.jsonl"
                if not p.is_file():
                    return self._error(HTTPStatus.NOT_FOUND, "run not found")
                return self._send_text(p.read_text(), "application/x-ndjson", f"threatsight-{rest[1]}.evidence.jsonl")
            if len(rest) == 3 and rest[0] == "runs" and rest[2] == "inspect.json" and RUN_ID.match(rest[1]):
                r = get_run(cfg, rest[1])
                if not r:
                    return self._error(HTTPStatus.NOT_FOUND, "run not found")
                log = eval_log([r], f"{r.get('title') or r['scenario']} ({r.get('agent')})")
                return self._send_text(json.dumps(log, indent=2), "application/json", inspect_filename(log))
            if len(rest) == 3 and rest[0] == "runs" and rest[2] == "verify":
                r = verify_run(cfg, rest[1])
                return self._send(200, r) if r else self._error(HTTPStatus.NOT_FOUND, "run not found")
            return self._error(HTTPStatus.NOT_FOUND, "not found")

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            parts = [p for p in path.split("/") if p]
            is_approval = len(parts) == 5 and parts[:3] == ["api", "world", "runs"] and parts[4] == "approvals"
            is_check = len(parts) == 5 and parts[:3] == ["api", "world", "connections"] and parts[4] == "check"
            is_hook = len(parts) == 5 and parts[:3] == ["api", "world", "integrations"] and DEST_ID.match(parts[3]) and parts[4] in {"test", "enable", "disable"}
            is_fix = parts[:3] == ["api", "world", "remediation"] and (len(parts) == 3 or (len(parts) == 5 and parts[4] in {"apply", "reject", "rollback"}))
            known = {"/api/world/runs", "/api/world/compare", "/api/world/connections", "/api/world/integrations",
                     "/api/world/settings", "/api/world/settings/probe"}
            if path not in known and not is_approval and not is_check and not is_hook and not is_fix:
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large")
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("body must be a JSON object")
                if is_fix:
                    status, prop = remediation_post(cfg, parts, body)
                    if prop is None:
                        return self._error(HTTPStatus.NOT_FOUND, "proposal not found")
                    return self._send(status, {**label_for(prop["profile"]), **prop})
                if is_approval:
                    r = decide(cfg, parts[3], body)
                    return self._send(200, r) if r else self._error(HTTPStatus.NOT_FOUND, "run not found")
                if is_check:
                    return self._send(200, {**DATA_LABEL, **check(cfg.connections.model(parts[3]))})
                if is_hook:
                    if parts[4] == "test":
                        row = cfg.integrations.test(parts[3])
                        return self._send(200, {**DATA_LABEL, "delivery": row}) if row else self._error(HTTPStatus.NOT_FOUND, "destination not found")
                    dest = cfg.integrations.set_enabled(parts[3], parts[4] == "enable")
                    return self._send(200, {**DATA_LABEL, "destination": dest.public()}) if dest else self._error(HTTPStatus.NOT_FOUND, "destination not found")
                if path == "/api/world/integrations":
                    return self._send(201, {**DATA_LABEL, "destination": cfg.integrations.add(body).public()})
                if path == "/api/world/compare":
                    return self._send(202, {**DATA_LABEL, **cfg.compare.start(body, cfg.compare_models())})
                if path == "/api/world/settings":
                    return self._send(200, cfg.update_settings(body))
                if path == "/api/world/settings/probe":
                    # Test a local server address before saving it. The saved key goes only to the saved address.
                    base = str(body.get("local_base") or cfg.llm_base).strip().rstrip("/")
                    key = str(body.get("local_key") or "").strip() or (cfg.llm_key if base == cfg.llm_base else None)
                    return self._send(200, {**DATA_LABEL, **probe(base, key)})
                if path == "/api/world/connections":
                    return self._send(201, {**DATA_LABEL, "connection": cfg.connections.add(body).public()})
                return self._send(201, execute(cfg, body))
            except rem.RemediationError as exc:
                return self._error(HTTPStatus.CONFLICT, str(exc))
            except (ValueError, PolicyError, json.JSONDecodeError) as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except ConnectionError as exc:
                return self._error(HTTPStatus.BAD_GATEWAY, f"model endpoint unreachable: {exc}")

        def do_DELETE(self) -> None:
            parts = [p for p in urlparse(self.path).path.split("/") if p]
            if len(parts) == 4 and parts[:3] == ["api", "world", "connections"] and ENDPOINT_ID.match(parts[3]):
                if cfg.connections.remove(parts[3]):
                    return self._send(200, {**DATA_LABEL, "removed": parts[3]})
                return self._error(HTTPStatus.NOT_FOUND, "connection not found")
            if len(parts) == 4 and parts[:3] == ["api", "world", "integrations"] and DEST_ID.match(parts[3]):
                if cfg.integrations.remove(parts[3]):
                    return self._send(200, {**DATA_LABEL, "removed": parts[3]})
                return self._error(HTTPStatus.NOT_FOUND, "destination not found")
            return self._error(HTTPStatus.NOT_FOUND, "not found")

    return Handler


def serve(cfg: Config, host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(cfg))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m threatsight_world.server")
    p.add_argument("--host", default=os.environ.get("THREATSIGHT_WORLD_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("THREATSIGHT_WORLD_PORT", "8092")))
    args = p.parse_args(argv)
    cfg = Config.from_env()
    cfg.compare.recover()
    httpd = serve(cfg, args.host, args.port)
    print(json.dumps({"event": "listening", "host": args.host, "port": args.port, "models": cfg.models(), "runs_dir": str(cfg.runs_dir)}), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
