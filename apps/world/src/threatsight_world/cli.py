"""Command line: run, retest and check agents. Exit code 0 = PASS, 1 = FAIL, 2 = INCONCLUSIVE."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from typing import Any

from threatsight_world import evidence as ev
from threatsight_world import profiles
from threatsight_world.assess import (
    LiveProvider,
    Provider,
    ReplayProvider,
    ScriptedProvider,
    retest,
    run_assessment,
    record_scenario,
    run_utility,
    write_recording,
)
from threatsight_world.inspect_log import eval_log
from threatsight_world.llm import OpenAICompatModel
from threatsight_world.policy import Gateway
from threatsight_world.scenarios import SCENARIOS, Scenario, scenarios_for

EXIT = {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2}


def _provider(args: argparse.Namespace) -> Provider:
    if args.model == "scripted":
        return ScriptedProvider()
    if args.model.startswith("replay:"):
        return ReplayProvider(args.model.split(":", 1)[1])
    if args.model == "openai":
        base = args.base_url or os.environ.get("THREATSIGHT_LLM_BASE_URL", "http://localhost:11434/v1")
        name = args.model_name or os.environ.get("THREATSIGHT_LLM_MODEL")
        if not name:
            raise SystemExit("--model-name (or THREATSIGHT_LLM_MODEL) is required with --model openai")
        key = os.environ.get(args.api_key_env) if args.api_key_env else None
        return LiveProvider(OpenAICompatModel(base, name, key))
    raise SystemExit("--model must be scripted, replay:<file> or openai")


def _worst(codes: list[str]) -> int:
    return max((EXIT[c] for c in codes), default=0) if "FAIL" not in codes else 1


def _summary(a: Any) -> dict[str, Any]:
    return {"model": a.model, "policy": a.policy, **a.verdict.to_dict(), "tool_calls": [{"name": t.name, "args": t.args, "allowed": t.allowed, "executed": t.executed, "rule": t.rule} for t in a.trace.attempts]}


def _inspect_record(sc: Scenario, a: Any, utility: Any = None) -> dict[str, Any]:
    stamp = time.gmtime()
    return {"id": time.strftime("%Y%m%dT%H%M%S", stamp) + "-" + uuid.uuid4().hex[:8], "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", stamp),
            "synthetic": True, "profile": sc.profile, "organisation": profiles.get(sc.profile).organisation,
            "scenario": sc.id, "title": sc.title, "agent": sc.agent, "control": sc.control.id, "mode": "run",
            "runs": [a.to_dict()], "utility": utility, "verdict": a.verdict.verdict}


def _write_inspect(args: argparse.Namespace, records: list[dict[str, Any]]) -> None:
    if getattr(args, "inspect_log", None) and records:
        os.makedirs(os.path.dirname(os.path.abspath(args.inspect_log)), exist_ok=True)
        with open(args.inspect_log, "w", encoding="utf-8") as f:
            json.dump(eval_log(records), f, indent=2)
        if not getattr(args, "json", False):
            print(f"Inspect AI log written to {args.inspect_log} (open with: inspect view --log-dir {os.path.dirname(os.path.abspath(args.inspect_log))})")


def _print(a: Any, label: str) -> None:
    v = a.verdict
    print(f"  {label:<8} {v.verdict:<12} {v.reason_code}  [{a.policy}]")
    for t in a.trace.attempts:
        state = "ran" if t.executed else "blocked"
        print(f"           tool {t.name} {json.dumps(t.args)} -> {state}" + (f" ({t.rule})" if t.rule else ""))


def cmd_list(args: argparse.Namespace) -> int:
    for sc in SCENARIOS.values():
        print(f"{sc.id:<24} {sc.profile:<8} {sc.agent:<20} {sc.control.id:<16} {sc.title}")
    return 0


def _gateway(policy: str, sc: Scenario) -> Gateway:
    """'hardened' means the scenario's own organisation's reviewed policy."""
    return Gateway.from_name(profiles.get(sc.profile).policy if policy == "hardened" else policy)


def _selected(args: argparse.Namespace) -> list[Scenario]:
    return list(SCENARIOS.values()) if args.profile == "all" else scenarios_for(args.profile)


def _log(args: argparse.Namespace) -> ev.EvidenceLog | None:
    return ev.EvidenceLog() if args.evidence else None


def _finish_log(args: argparse.Namespace, log: ev.EvidenceLog | None) -> None:
    if log and args.evidence:
        log.write(args.evidence)
        ok, _, msg = log.verify()
        print(f"evidence: {args.evidence} ({msg}{'' if log.key else ', unsigned'})")


def cmd_run(args: argparse.Namespace) -> int:
    sc = SCENARIOS[args.scenario]
    log = _log(args)
    a = run_assessment(sc, _provider(args), _gateway(args.policy, sc), log)
    if args.record:
        write_recording(args.record, a, sc)
    if args.json:
        print(json.dumps({"scenario": sc.id, **_summary(a)}, indent=2))
    else:
        print(f"{sc.id}: {sc.title}")
        _print(a, "result")
    _finish_log(args, log)
    return EXIT[a.verdict.verdict]


def cmd_retest(args: argparse.Namespace) -> int:
    sc = SCENARIOS[args.scenario]
    log = _log(args)
    r = retest(sc, _provider(args), _gateway(args.policy, sc), log)
    if args.json:
        print(json.dumps({"scenario": sc.id, "before": _summary(r["before"]), "after": _summary(r["after"]), "utility": r["utility"]}, indent=2))
    else:
        print(f"{sc.id}: {sc.title}")
        _print(r["before"], "before")
        _print(r["after"], "after")
        done = [u for u in r["utility"] if u["passed"] is not None]
        print(f"  utility  {sum(1 for u in done if u['passed'])}/{len(done)} routine tasks pass under the policy")
    _finish_log(args, log)
    return EXIT[r["after"].verdict.verdict]


def cmd_suite(args: argparse.Namespace) -> int:
    """Pytest for agents: run every scenario under one policy; non-zero exit on any FAIL."""
    provider = _provider(args)
    log = _log(args)
    codes: list[str] = []
    rows = []
    records = []
    for sc in _selected(args):
        gw = _gateway(args.policy, sc)
        a = run_assessment(sc, provider, gw, log)
        codes.append(a.verdict.verdict)
        u = run_utility(sc, provider, gw)
        rows.append({"scenario": sc.id, **_summary(a), "utility": u})
        records.append(_inspect_record(sc, a, u))
        if not args.json:
            print(f"{sc.id:<24} {a.verdict.verdict:<12} {a.verdict.reason_code}")
    if args.json:
        print(json.dumps(rows, indent=2))
    _finish_log(args, log)
    _write_inspect(args, records)
    return _worst(codes)


def cmd_verify(args: argparse.Namespace) -> int:
    ok, idx, msg = ev.verify_records(ev.load(args.file), os.environ.get("THREATSIGHT_EVIDENCE_KEY"))
    print(msg)
    return 0 if ok else 1


def cmd_probes(args: argparse.Namespace) -> int:
    from collections import Counter
    from threatsight_world.probes import TECHNIQUES
    from threatsight_world.scenarios import SCENARIOS
    from threatsight_world.variants import tagged_variants_for

    counts = {sid: Counter(v.technique for v in tagged_variants_for(sc)) for sid, sc in SCENARIOS.items()}
    rows = [
        {"id": t.id, "name": t.name, "source": t.source, "owasp": list(t.owasp), "agentic": list(t.agentic), "atlas": list(t.atlas),
         "scenarios": {sid: c[t.id] for sid, c in counts.items() if c[t.id]}}
        for t in TECHNIQUES.values()
    ]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for r in rows:
        print(f"{r['id']:<34} {r['source']:<34} {len(r['scenarios'])} scenarios  {', '.join(r['atlas'])}")
    print(f"\n{sum(sum(c.values()) for c in counts.values())} variants across {len(counts)} scenarios")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from collections import Counter
    from threatsight_world.probes import TECHNIQUES
    from threatsight_world.variants import tagged_variants_for, with_message

    provider = _provider(args)
    gw_open = Gateway.from_name("open")
    results: dict[str, Any] = {}
    cycled_scenarios: list[str] = []

    for sc in _selected(args):
        gw_hard = _gateway("hardened", sc)
        variants = tagged_variants_for(sc)
        if args.technique:
            variants = [v for v in variants if v.technique.startswith(args.technique)]
            if not variants:
                continue
        runs = args.repeat or len(variants)
        if runs > len(variants):
            cycled_scenarios.append(sc.id)

        verdicts: list[str] = []
        by_technique: dict[str, Counter[str]] = {}
        hostile_attempts_count = 0
        total_tool_calls = 0
        valid_tool_calls = 0

        for i in range(runs):
            variant = variants[i % len(variants)]
            v_sc = with_message(sc, variant.message)
            a = run_assessment(v_sc, provider, gw_open)
            verdicts.append(a.verdict.verdict)
            by_technique.setdefault(variant.technique, Counter())[a.verdict.verdict] += 1

            if any(sc.control.is_hostile_attempt(attempt) for attempt in a.trace.attempts):
                hostile_attempts_count += 1

            for attempt in a.trace.attempts:
                total_tool_calls += 1
                if "_invalid" not in attempt.args:
                    valid_tool_calls += 1

        utility_res = run_utility(sc, provider, gw_hard)
        evaluated_tasks = [u for u in utility_res if u["passed"] is not None]
        if evaluated_tasks:
            routine_task_pass_rate = sum(1 for u in evaluated_tasks if u["passed"]) / len(evaluated_tasks)
        else:
            routine_task_pass_rate = 1.0

        c = Counter(verdicts)
        attempt_rate = hostile_attempts_count / runs if runs else 0.0
        valid_rate = valid_tool_calls / total_tool_calls if total_tool_calls else 1.0

        results[sc.id] = {
            "title": sc.title,
            "repeat": runs,
            "variants_available": len(variants),
            "cycled": runs > len(variants),
            "verdicts": {
                "FAIL": c.get("FAIL", 0),
                "PASS": c.get("PASS", 0),
                "INCONCLUSIVE": c.get("INCONCLUSIVE", 0),
            },
            "attempt_rate": round(attempt_rate, 4),
            "valid_tool_call_rate": round(valid_rate, 4),
            "routine_task_pass_rate": round(routine_task_pass_rate, 4),
            "by_technique": {
                t: {"source": TECHNIQUES[t].source, "atlas": list(TECHNIQUES[t].atlas), "agentic": list(TECHNIQUES[t].agentic),
                    "FAIL": n.get("FAIL", 0), "PASS": n.get("PASS", 0), "INCONCLUSIVE": n.get("INCONCLUSIVE", 0)}
                for t, n in by_technique.items()
            },
        }

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        if cycled_scenarios:
            print(f"Note: repeat count ({args.repeat}) exceeds available variants for {', '.join(cycled_scenarios)}; cycled variants.")
        print(f"{'Scenario':<24} {'FAIL':<6} {'PASS':<6} {'INCONC':<8} {'Attempt%':<10} {'ValidTool%':<12} {'RoutinePass%':<12}")
        print("-" * 80)
        for sid, d in results.items():
            v = d["verdicts"]
            print(f"{sid:<24} {v['FAIL']:<6} {v['PASS']:<6} {v['INCONCLUSIVE']:<8} {d['attempt_rate']*100:<10.1f} {d['valid_tool_call_rate']*100:<12.1f} {d['routine_task_pass_rate']*100:<12.1f}")

    return 0


def cmd_record(args: argparse.Namespace) -> int:
    """Record every scenario (attack plus routine tasks) for replay in the web demo."""
    from pathlib import Path

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    provider = _provider(args)
    for sc in SCENARIOS.values():
        a, tasks, extra = record_scenario(sc, provider, args.tries)
        write_recording(out / f"{sc.id}.jsonl", a, sc, extra, tasks)
        state = "attempted" if extra["hostile_attempt"] else "no attempt"
        print(f"{sc.id:<24} {a.verdict.verdict:<12} {state} after {extra['tries']}/{args.tries} tries -> {out / (sc.id + '.jsonl')}")
    return 0


def _proposer(args: argparse.Namespace) -> Any:
    from threatsight_world import remediate as rem

    if args.proposer == "heuristic":
        return rem.HeuristicProposer()
    if args.proposer == "openai":
        base = args.base_url or os.environ.get("THREATSIGHT_LLM_BASE_URL", "http://localhost:11434/v1")
        name = args.proposer_model or os.environ.get("THREATSIGHT_REMEDIATION_MODEL") or os.environ.get("THREATSIGHT_LLM_MODEL")
        if not name:
            raise SystemExit("--proposer-model (or THREATSIGHT_REMEDIATION_MODEL) is required with --proposer openai")
        key = os.environ.get(args.api_key_env) if args.api_key_env else None
        return rem.ModelProposer(OpenAICompatModel(base, name, key))
    raise SystemExit("--proposer must be heuristic or openai")


def _print_proposal(p: dict[str, Any]) -> None:
    print(f"{p['id']}  {p['scenario']}  [{p['status']}]  policy v{p['base_version']}")
    f = p["finding"]
    print(f"  finding  {f['failed']}/{len(f['variants'])} attack variants cause harm ({p['control']})")
    for i, a in enumerate(p["attempts"], 1):
        rule = a["rule"]["id"] if a.get("rule") else json.dumps(a.get("raw"))[:80]
        print(f"  try {i}    {rule}: {a['why']}")
    if p.get("proof"):
        b, a = p["proof"]["attack"]["before"], p["proof"]["attack"]["after"]
        done = [u for u in p["proof"]["utility"] if u["passed"] is not None]
        print(f"  proof    attacks FAIL {b['FAIL']} -> {a['FAIL']}, stopped {a['PASS']}; routine {sum(1 for u in done if u['passed'])}/{len(done)} pass")
        for line in p["diff"]:
            print(f"  diff     {line}")
    for h in p.get("history", []):
        print(f"  {h['action']:<8} by {h['by']} at {h['at']}" + (f" -> v{h['version']}" if h.get("version") else "") + (f" post-check {h['post_check']['verdict']}" if h.get("post_check") else ""))
    if p.get("evidence"):
        print(f"  evidence {p['evidence']['message']}")


def cmd_remediate(args: argparse.Namespace) -> int:
    """Verified remediation: propose a guardrail fix, prove it by replay, apply it with a named approver, roll it back."""
    from pathlib import Path

    from threatsight_world import remediate as rem

    root = Path(args.store)
    try:
        if args.action == "propose":
            sc = SCENARIOS[args.target]
            p = rem.propose(sc, _provider(args), _proposer(args), rem.Store(root, sc.profile), args.max_candidates)
        elif args.action == "status":
            store = rem.Store(root, args.profile)
            print(f"{args.profile}: live policy v{store.head()} ({len(store.current()['rules'])} rules)")
            for v in store.versions():
                print(f"  v{v['version']:<3} {v['created']}  {v['change']['op']:<12} {v['change'].get('rule', {}).get('id') or v['change'].get('rule_id')}  by {v['by']}")
            for q in store.proposals():
                print(f"  {q['id']}  {q['scenario']:<24} {q['status']}")
            return 0
        else:
            store = rem.Store(root, args.profile)
            if args.action == "apply":
                p = rem.apply(store, args.target, args.approver, _provider(args), SCENARIOS)
            elif args.action == "reject":
                p = rem.reject(store, args.target, args.approver, args.note or "")
            else:
                p = rem.rollback(store, args.target, args.approver)
    except rem.RemediationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    if args.json:
        print(json.dumps(p, indent=2))
    else:
        _print_proposal(p)
    return 0 if p["status"] in {"proposed", "applied", "rejected", "rolled_back", "nothing_to_fix"} else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threatsight-world", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, policy_default: str) -> None:
        sp.add_argument("--policy", default=policy_default, help="open, hardened (the scenario's own policy), nordvik-hardened, helio-hardened or a path to a policy .json")
        sp.add_argument("--model", default="scripted", help="scripted, replay:<file> or openai")
        sp.add_argument("--base-url", help="OpenAI-compatible base URL, e.g. http://localhost:11434/v1")
        sp.add_argument("--model-name", help="model name at that endpoint")
        sp.add_argument("--api-key-env", help="environment variable holding an API key, if the endpoint needs one")
        sp.add_argument("--evidence", help="write a hash-chained evidence log to this file")
        sp.add_argument("--json", action="store_true")

    sub.add_parser("list", help="list scenarios").set_defaults(fn=cmd_list)
    r = sub.add_parser("run", help="run one scenario once")
    r.add_argument("scenario", choices=sorted(SCENARIOS))
    r.add_argument("--record", help="write the run to a JSONL recording for later replay")
    common(r, "open")
    r.set_defaults(fn=cmd_run)
    t = sub.add_parser("retest", help="attack, apply a policy, attack again, check routine tasks")
    t.add_argument("scenario", choices=sorted(SCENARIOS))
    common(t, "hardened")
    t.set_defaults(fn=cmd_retest)
    s = sub.add_parser("suite", help="run every scenario under one policy; exit 1 on any FAIL")
    common(s, "hardened")
    s.add_argument("--profile", default="nordvik", choices=["nordvik", "helio", "all"], help="which organisation's scenarios to run")
    s.add_argument("--inspect-log", help="also write the results as an Inspect AI evaluation log (.json) to this file")
    s.set_defaults(fn=cmd_suite)
    v = sub.add_parser("verify", help="check an evidence log")
    v.add_argument("file")
    v.set_defaults(fn=cmd_verify)
    rc = sub.add_parser("record", help="record every scenario (attack + routine tasks) for replay in the web demo")
    rc.add_argument("--out", required=True, help="directory for <scenario>.jsonl recordings")
    rc.add_argument("--tries", type=int, default=3, help="attack tries per scenario; keeps the first with a hostile attempt")
    common(rc, "open")
    rc.set_defaults(fn=cmd_record)
    b = sub.add_parser("bench", help="benchmark attack variants under open policy and check routine tasks")
    b.add_argument("--repeat", type=int, default=1, help="number of attack runs per scenario; 0 runs every variant once")
    b.add_argument("--model", default="openai", help="scripted, replay:<file> or openai")
    b.add_argument("--base-url", help="OpenAI-compatible base URL")
    b.add_argument("--model-name", help="model name at that endpoint")
    b.add_argument("--api-key-env", help="environment variable holding an API key")
    b.add_argument("--json", action="store_true")
    b.add_argument("--profile", default="nordvik", choices=["nordvik", "helio", "all"], help="which organisation's scenarios to run")
    b.add_argument("--technique", help="only variants whose technique id starts with this, such as garak, pyrit, agentdojo or garak-dan")
    b.set_defaults(fn=cmd_bench)
    pr = sub.add_parser("probes", help="list the attack techniques and how many variants each scenario has")
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(fn=cmd_probes)
    m = sub.add_parser("remediate", help="propose a guardrail fix, prove it by replaying the attack, apply it with a named approver, roll it back")
    m.add_argument("action", choices=["propose", "apply", "reject", "rollback", "status"])
    m.add_argument("target", nargs="?", help="scenario id for propose; proposal id for apply, reject and rollback")
    m.add_argument("--store", default="runs/remediation", help="directory for policy versions, proposals and evidence")
    m.add_argument("--profile", default="nordvik", choices=sorted(profiles.PROFILES), help="organisation for apply, reject, rollback and status")
    m.add_argument("--proposer", default="heuristic", help="heuristic (no model) or openai (a local model picks the fix)")
    m.add_argument("--proposer-model", help="model name for --proposer openai, e.g. qwen2.5:7b")
    m.add_argument("--max-candidates", type=int, default=3, help="candidates to try before leaving the finding open")
    m.add_argument("--approver", help="the named person who applies, rejects or rolls back")
    m.add_argument("--note", help="reason for a rejection")
    m.add_argument("--model", default="scripted", help="the agent under test: scripted, replay:<file> or openai")
    m.add_argument("--base-url", help="OpenAI-compatible base URL, e.g. http://localhost:11434/v1")
    m.add_argument("--model-name", help="agent model name at that endpoint")
    m.add_argument("--api-key-env", help="environment variable holding an API key, if the endpoint needs one")
    m.add_argument("--json", action="store_true")
    m.set_defaults(fn=cmd_remediate)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "remediate":
        if args.action == "propose" and args.target not in SCENARIOS:
            raise SystemExit(f"propose needs a scenario id: {', '.join(sorted(SCENARIOS))}")
        if args.action in {"apply", "reject", "rollback"} and not (args.target and args.approver):
            raise SystemExit(f"{args.action} needs a proposal id and --approver")
    try:
        return args.fn(args)
    except ConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
