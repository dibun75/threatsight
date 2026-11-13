"""Flat exports of runs and comparisons, as JSON or CSV, for Power BI, Excel or a SIEM import.

One row per run (its final verdict) and one row per comparison cell. Lists such as the MITRE ATLAS
techniques are joined with "; " in CSV. Every row says synthetic=true.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from threatsight_world.scenarios import SCENARIOS

RUN_COLUMNS = ["id", "created", "profile", "organisation", "scenario", "title", "agent", "control", "control_title", "mode", "model", "policy", "verdict", "reason_code",
               "summary", "approver", "duration_ms", "owasp_llm", "owasp_agentic", "mitre_atlas", "evidence_records", "evidence_head",
               "evidence_valid", "synthetic"]
CELL_COLUMNS = ["comparison_id", "created", "profile", "status", "model", "model_label", "scenario", "agent", "control", "verdict_without_policy",
                "reason_without_policy", "verdict_with_policy", "reason_with_policy", "work_passed", "work_total", "error", "ms",
                "owasp_llm", "owasp_agentic", "mitre_atlas", "synthetic"]


def control_tags(scenario_id: str) -> dict[str, list[str]]:
    sc = SCENARIOS.get(scenario_id)
    if sc is None:
        return {"owasp_llm": [], "owasp_agentic": [], "mitre_atlas": []}
    return {"owasp_llm": list(sc.control.tags), "owasp_agentic": list(sc.control.agentic), "mitre_atlas": list(sc.control.atlas)}


def run_row(r: dict[str, Any]) -> dict[str, Any]:
    last = r["runs"][-1]
    approval = next((a for a in reversed(r.get("approvals", []))), None)
    verdict = approval["verdict"] if approval and approval["verdict"]["verdict"] == r.get("verdict") else last["verdict"]
    sc = SCENARIOS.get(r["scenario"])
    return {
        "id": r["id"], "created": r["created"], "profile": r.get("profile", "nordvik"), "organisation": r.get("organisation"),
        "scenario": r["scenario"], "title": r.get("title"), "agent": r.get("agent"),
        "control": r.get("control"), "control_title": sc.control.title if sc else None, "mode": r.get("mode"),
        "model": last["model"], "policy": last["policy"], "verdict": r.get("verdict"), "reason_code": verdict["reason_code"],
        "summary": verdict["summary"], "approver": approval["approver"] if approval else None, "duration_ms": r.get("duration_ms"),
        **control_tags(r["scenario"]),
        "evidence_records": r["evidence"]["records"], "evidence_head": r["evidence"]["head"], "evidence_valid": r["evidence"]["valid"],
        "synthetic": bool(r.get("synthetic")),
    }


def run_rows(runs_dir: Path, limit: int = 1000) -> list[dict[str, Any]]:
    if not runs_dir.is_dir():
        return []
    out = []
    for p in sorted(runs_dir.glob("*.json"), reverse=True):
        if len(out) >= limit:
            break
        try:
            r = json.loads(p.read_text())
            if isinstance(r, dict) and r.get("synthetic") and r.get("runs"):
                out.append(run_row(r))
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            continue
    return out


def cell_rows(compare_dir: Path, limit: int = 100) -> list[dict[str, Any]]:
    if not compare_dir.is_dir():
        return []
    out = []
    for p in sorted(compare_dir.glob("cmp-*.json"), reverse=True)[:limit]:
        try:
            job = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        for m in job.get("models", []):
            for s in job.get("scenarios", []):
                c = job.get("cells", {}).get(f"{s['id']}|{m['id']}")
                if c is None:
                    continue
                before, after = c.get("before") or {}, c.get("after") or {}
                out.append({
                    "comparison_id": job["id"], "created": job.get("created"), "profile": job.get("profile", "nordvik"), "status": job.get("status"), "model": m["id"],
                    "model_label": m.get("label"), "scenario": s["id"], "agent": s.get("agent"), "control": s.get("control"),
                    "verdict_without_policy": before.get("verdict"), "reason_without_policy": before.get("reason_code"),
                    "verdict_with_policy": after.get("verdict"), "reason_with_policy": after.get("reason_code"),
                    "work_passed": (c.get("utility") or {}).get("passed"), "work_total": (c.get("utility") or {}).get("total"),
                    "error": c.get("error"), "ms": c.get("ms"), **control_tags(s["id"]), "synthetic": True,
                })
    return out


def _cell(value: Any) -> Any:
    if isinstance(value, list):
        value = "; ".join(value)
    if value is None:
        return ""
    # A text cell starting with = + - @ would run as a formula in Excel; prefix it so it stays text.
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        return "'" + value
    return value


def to_csv(rows: list[dict[str, Any]], columns: list[str]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore", lineterminator="\r\n")
    w.writeheader()
    for row in rows:
        w.writerow({k: _cell(v) for k, v in row.items()})
    return buf.getvalue()
