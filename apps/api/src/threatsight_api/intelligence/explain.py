from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.domain.extraction import looks_like_instruction
from threatsight_api.persistence.models import (
    AgentEvent,
    AISystemProfile,
    AISystemRecord,
    AssuranceRunRecord,
    ControlRecord,
    IntelTechnique,
    IntelTechniqueControl,
    IntelThreat,
)
from threatsight_api.services.dashboard import load_system_graph
from threatsight_api.services.identity import identity_for

UNKNOWN = "UNKNOWN"


def collect_facts(db: Session, system: AISystemRecord) -> dict:
    graph = load_system_graph(db, system)
    profile = db.scalar(select(AISystemProfile).where(AISystemProfile.ai_system_id == system.id))
    events = list(
        db.scalars(
            select(AgentEvent)
            .where(AgentEvent.ai_system_id == system.id)
            .order_by(AgentEvent.occurred_at.desc())
            .limit(20)
        )
    )
    runs = list(
        db.scalars(
            select(AssuranceRunRecord)
            .where(AssuranceRunRecord.ai_system_id == system.id)
            .order_by(AssuranceRunRecord.started_at.desc())
            .limit(8)
        )
    )
    facts: dict[str, dict] = {}
    statements: list[dict] = []
    missing: list[str] = []

    def add(fact_id: str, text: str, *, source_type: str, source_id: str | None, href: str) -> None:
        if looks_like_instruction(text) or "COMPLIANT" in text.upper():
            return
        facts[fact_id] = {
            "text": text,
            "source_type": source_type,
            "source_id": source_id,
            "href": href,
        }
        statements.append({"text": text, "fact_id": fact_id})

    labelled = "labelled synthetic " if system.name == "Order support demo" else ""
    ident = identity_for(system)
    add(
        "system",
        f"Registered {labelled}AI system '{ident['display_name']}' (identifier {ident['technical_identifier']}) is owned by {system.owner} in environment {system.environment}.",
        source_type="ai_system",
        source_id=str(system.id),
        href=f"/systems/{system.id}",
    )
    purpose = (profile.purpose if profile and profile.purpose else system.description or "").strip()
    if purpose:
        add(
            "profile",
            f"Recorded purpose: {purpose}",
            source_type="ai_system_profile",
            source_id=str(profile.id) if profile else str(system.id),
            href=f"/systems/{system.id}",
        )
    else:
        missing.append("purpose")
    data_categories = list(profile.data_categories) if profile and profile.data_categories else []
    users = list(profile.users_subjects) if profile and profile.users_subjects else []
    capabilities = list(profile.capabilities) if profile and profile.capabilities else []
    if data_categories:
        add(
            "data",
            f"Recorded data categories: {', '.join(str(item) for item in data_categories)}.",
            source_type="ai_system_profile",
            source_id=str(profile.id) if profile else None,
            href=f"/systems/{system.id}",
        )
    else:
        missing.append("data_categories")
    if users:
        add(
            "users",
            f"Recorded users/subjects: {', '.join(str(item) for item in users)}.",
            source_type="ai_system_profile",
            source_id=str(profile.id) if profile else None,
            href=f"/systems/{system.id}",
        )
    else:
        missing.append("users_subjects")
    if capabilities:
        names = [
            item.get("name") if isinstance(item, dict) else str(item) for item in capabilities
        ]
        add(
            "capabilities",
            f"Recorded capabilities/tools: {', '.join(str(item) for item in names)}.",
            source_type="ai_system_profile",
            source_id=str(profile.id) if profile else None,
            href=f"/systems/{system.id}",
        )
    else:
        missing.append("capabilities")
    if profile and profile.missing:
        missing.extend(str(item) for item in profile.missing)

    if not graph["controls"]:
        missing.append("controls")
    for control in graph["controls"]:
        add(
            f"control:{control.identifier}",
            (
                f"Control {control.identifier} ({control.title}) has assurance_status "
                f"{control.assurance_status} and latest technical verdict "
                f"{control.latest_verdict or UNKNOWN}."
            ),
            source_type="control",
            source_id=str(control.id),
            href=f"/controls/{control.id}",
        )
        if control.identifier == "CTRL-002":
            add(
                "threat:tool_abuse",
                "Informational threat mapping: unauthorized tool execution is in scope for CTRL-002 via curated tool-abuse techniques. This is not a live feed.",
                source_type="intel_threat",
                source_id=None,
                href="/threats/tool_abuse",
            )

    if not graph["requirements"]:
        missing.append("requirements")
    for requirement in graph["requirements"][:8]:
        add(
            f"requirement:{requirement.id}",
            f"Requirement '{requirement.title}' is recorded with status {requirement.status}.",
            source_type="requirement",
            source_id=str(requirement.id),
            href=f"/requirements/{requirement.id}",
        )

    if not graph["findings"]:
        missing.append("findings")
    for finding in graph["findings"][:8]:
        add(
            f"finding:{finding.id}",
            f"Finding '{finding.title}' is {finding.status} with observed verdict {finding.verdict} and severity {finding.severity}.",
            source_type="finding",
            source_id=str(finding.id),
            href=f"/findings/{finding.id}",
        )

    if not graph["evidence"]:
        missing.append("evidence")
    for evidence in graph["evidence"][:8]:
        add(
            f"evidence:{evidence.id}",
            f"Evidence '{evidence.title}' is recorded with status {evidence.status}.",
            source_type="evidence",
            source_id=str(evidence.id),
            href=f"/evidence/{evidence.id}",
        )

    if not runs:
        missing.append("assurance_tests")
    recommended = None
    recommended_href = "/assurance"
    for run in runs:
        kind = "retest" if run.parent_run_id else "assessment"
        add(
            f"run:{run.id}",
            f"{kind.title()} {run.scenario_key} finished with verdict {run.verdict} ({run.reason_code}). LLM output did not authorize this result.",
            source_type="assurance_run",
            source_id=str(run.id),
            href="/assurance",
        )
        if run.verdict == "FAIL" and recommended is None:
            recommended = "Record gateway remediation, then confirm AUTH-02 as a parent-linked retest. This is not a legal conclusion."
            recommended_href = "/assurance"
        elif run.verdict == "PASS" and recommended is None:
            recommended = "Review freshness and keep AUTH-02 parent-linked history. This is technical assurance, not certification."

    if not events:
        missing.append("agent_events")
    for event in events[:8]:
        authorized = (event.authorization_context or {}).get("authorized")
        add(
            f"event:{event.id}",
            (
                f"Passive {event.source_kind} observation recorded tool '{event.tool_name or UNKNOWN}' "
                f"with authorization.authorized={authorized if authorized is not None else UNKNOWN}. "
                "Ingest is not a runtime firewall."
            ),
            source_type="agent_event",
            source_id=str(event.id),
            href=f"/systems/{system.id}",
        )

    control_ids = [item.id for item in graph["controls"]]
    if control_ids:
        for link in db.scalars(
            select(IntelTechniqueControl).where(IntelTechniqueControl.control_id.in_(control_ids))
        ):
            technique = db.get(IntelTechnique, link.technique_id)
            if technique is None:
                continue
            threat = db.get(IntelThreat, technique.threat_id)
            add(
                f"technique:{technique.key}",
                (
                    f"Technique {technique.title} ({technique.key}) affects capability "
                    f"{technique.affected_capability} under threat {threat.key if threat else UNKNOWN}. Informational only."
                ),
                source_type="intel_technique",
                source_id=str(technique.id),
                href=f"/threats/{threat.key if threat else ''}/{technique.key}",
            )

    if recommended is None:
        if any(
            item.assurance_status == "GAP_DETECTED" and item.latest_verdict != "PASS" for item in graph["controls"]
        ):
            recommended = "Open the control with GAP_DETECTED and confirm a sandboxed CTRL-002 test if evidence is missing."
        elif missing:
            recommended = "Record the UNKNOWN fields on this system before treating the posture as complete."
            recommended_href = f"/systems/{system.id}"
        else:
            recommended = "Review freshness and open findings. Counts are not a legal compliance result."

    unique_missing = []
    for item in missing:
        if item not in unique_missing:
            unique_missing.append(item)

    return {
        "facts": facts,
        "statements": statements,
        "missing": unique_missing,
        "recommended_action": recommended,
        "recommended_href": recommended_href,
        "confidence": 0.35 if unique_missing else 0.72,
        "uncertainty": (
            "Missing recorded facts are listed as UNKNOWN. This explanation does not invent evidence or authorize actions."
        ),
        "purpose": purpose or UNKNOWN,
        "data_categories": data_categories,
        "users_subjects": users,
        "capabilities": capabilities,
        "control_identifier": next((item.identifier for item in graph["controls"]), None),
        "requirement_title": next((item.title for item in graph["requirements"]), None),
        "correlations": _correlations(db, graph["controls"]),
        "legal_compliance_claim": False,
    }


def heuristic_explain(db: Session, system: AISystemRecord) -> dict:
    bundle = collect_facts(db, system)
    linked = []
    for item in bundle["statements"]:
        fact = bundle["facts"].get(item["fact_id"])
        if not fact:
            continue
        linked.append(
            {
                "text": item["text"],
                "fact_id": item["fact_id"],
                "source_type": fact["source_type"],
                "source_id": fact["source_id"],
                "href": fact["href"],
            }
        )
    return {
        "system_id": str(system.id),
        "llm_authored": False,
        "llm_available": False,
        "provider": "heuristic",
        "model": "ops-rule-v1",
        "prompt_version": "m13-explain-v1",
        "legal_compliance_claim": False,
        "confidence": bundle["confidence"],
        "uncertainty": bundle["uncertainty"],
        "statements": linked,
        "recommended_action": {
            "text": bundle["recommended_action"],
            "href": bundle["recommended_href"],
        },
        "missing": bundle["missing"],
        "never_authorizes": True,
        "verdict_authority": "deterministic_policy",
        "runtime_firewall": False,
    }


def merge_llm_explain(heuristic: dict, llm_out: dict, facts: dict) -> dict:
    allowed = facts
    statements = []
    for item in llm_out.get("statements") or []:
        fact_id = item.get("fact_id")
        fact = allowed.get(fact_id)
        text = str(item.get("text") or "").strip()
        if not fact or not text or looks_like_instruction(text) or "COMPLIANT" in text.upper():
            continue
        statements.append(
            {
                "text": text[:2000],
                "fact_id": fact_id,
                "source_type": fact["source_type"],
                "source_id": fact["source_id"],
                "href": fact["href"],
            }
        )
    if not statements:
        statements = heuristic["statements"]
    action_text = llm_out.get("recommended_action") or heuristic["recommended_action"]["text"]
    if looks_like_instruction(str(action_text)) or "COMPLIANT" in str(action_text).upper():
        action_text = heuristic["recommended_action"]["text"]
    missing = list(dict.fromkeys([*(llm_out.get("missing") or []), *heuristic["missing"]]))
    return {
        **heuristic,
        "llm_authored": True,
        "statements": statements,
        "recommended_action": {
            "text": str(action_text)[:2000],
            "href": heuristic["recommended_action"]["href"],
        },
        "missing": missing,
        "confidence": float(llm_out.get("confidence") or heuristic["confidence"]),
        "uncertainty": str(llm_out.get("uncertainty") or heuristic["uncertainty"]),
        "legal_compliance_claim": False,
        "never_authorizes": True,
        "verdict_authority": "deterministic_policy",
    }


def _correlations(db: Session, controls: list[ControlRecord]) -> list[dict]:
    if not controls:
        return []
    ids = [item.id for item in controls]
    by_id = {item.id: item.identifier for item in controls}
    rows = []
    for link in db.scalars(select(IntelTechniqueControl).where(IntelTechniqueControl.control_id.in_(ids))):
        technique = db.get(IntelTechnique, link.technique_id)
        if technique is None:
            continue
        threat = db.get(IntelThreat, technique.threat_id)
        rows.append(
            {
                "threat_key": threat.key if threat else UNKNOWN,
                "technique_key": technique.key,
                "control_identifier": by_id.get(link.control_id),
                "affected_capability": technique.affected_capability,
                "informational_only": True,
            }
        )
    return rows[:50]
