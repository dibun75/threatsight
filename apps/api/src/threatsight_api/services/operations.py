from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.assurance.engine import DEMO_ENVIRONMENT, DEMO_SYSTEM_NAME
from threatsight_api.persistence.models import (
    AISystemRecord,
    AssuranceRunRecord,
    ControlRecord,
    FindingRecord,
    IntelTechnique,
    IntelTechniqueControl,
    IntelThreat,
    RemediationRecord,
)
from threatsight_api.services.copy import counted, humanize_action
from threatsight_api.services.identity import SHOWCASE_DISPLAY_NAME, SHOWCASE_ORG, identity_for

HIGH_SEVERITY = frozenset({"high", "critical"})
EVIDENCE_STATES = ("tested", "mapped", "catalogued", "not_assessed")
PROVEN_THREAT_KEYS = frozenset({"tool_abuse"})


def open_findings_only(findings: list[FindingRecord]) -> list[FindingRecord]:
    return [item for item in findings if item.status == "open"]


def technical_gaps(controls: list[ControlRecord]) -> int:
    return sum(
        1
        for item in controls
        if item.assurance_status == "GAP_DETECTED" and item.latest_verdict != "PASS"
    )


def build_operations(
    db: Session,
    *,
    systems: list[AISystemRecord],
    controls: list[ControlRecord],
    findings: list[FindingRecord],
    runs: list[AssuranceRunRecord],
    freshness: dict,
    pending_docs: int = 0,
    include_document_queue: bool = True,
) -> dict:
    open_findings = open_findings_only(findings)
    high = [item for item in open_findings if item.severity in HIGH_SEVERITY]
    high.sort(key=lambda item: item.created_at, reverse=True)
    gaps = technical_gaps(controls)
    validated = sum(1 for item in controls if item.assurance_status == "VALIDATED")
    tested = sum(1 for item in controls if item.latest_verdict)
    pass_runs = sum(1 for item in runs if item.verdict == "PASS")
    fail_runs = sum(1 for item in runs if item.verdict == "FAIL")
    demo = next(
        (item for item in systems if item.name == DEMO_SYSTEM_NAME and item.environment == DEMO_ENVIRONMENT),
        None,
    )
    landscape = threat_landscape(db, controls=controls, runs=runs)
    mapped = sum(1 for item in landscape if item["evidence_state"] == "mapped")
    tested_threats = sum(1 for item in landscape if item["evidence_state"] == "tested")
    journey = build_journey(db, demo=demo, findings=findings, runs=runs, controls=controls)
    action = _action_queue(
        systems=systems,
        high_count=len(high),
        gaps=gaps,
        untested=sum(1 for item in controls if not item.latest_verdict),
        stale=int(freshness.get("stale_controls") or 0),
        pending_docs=pending_docs if include_document_queue else 0,
        demo=demo,
        findings=high,
        journey=journey,
    )
    primary_count = sum(1 for item in systems if identity_for(item)["canonical_demo"])
    supporting = sum(1 for item in systems if identity_for(item)["supporting_inventory"])
    questions = [
        {
            "id": "systems",
            "question": "What AI systems do we have?",
            "answer": (
                f"{SHOWCASE_ORG} operates {SHOWCASE_DISPLAY_NAME}."
                if demo is not None
                else (
                    counted(len(systems), "registered system") + "."
                    if systems
                    else "Inventory is empty until a system is registered."
                )
            ),
            "href": f"/systems/{demo.id}" if demo is not None else "/systems",
            "count": primary_count or len(systems),
        },
        {
            "id": "threats",
            "question": "What threats matter?",
            "answer": (
                f"{len(landscape)} curated AI threat categories; {tested_threats} tested, {mapped} mapped. "
                "Catalogued is not tested. Informational catalog, not a live feed."
            ),
            "href": "/threats",
            "count": len(landscape),
        },
        {
            "id": "exposure",
            "question": "What are we exposed to?",
            "answer": (
                f"{counted(len(high), 'high or critical open finding')}; "
                f"{counted(len(open_findings), 'open finding')} overall. Untested is not FAIL."
            ),
            "href": "/findings",
            "count": len(high),
        },
        {
            "id": "controls",
            "question": "Which controls protect us?",
            "answer": (
                f"{counted(len(controls), 'control')}; {counted(gaps, 'control')} in GAP_DETECTED. "
                "CTRL-002 is the tool-authorization control."
            ),
            "href": "/controls",
            "count": len(controls),
        },
        {
            "id": "proven",
            "question": "What has actually been tested/proven?",
            "answer": (
                f"{counted(tested, 'control', verb_one='has', verb_many='have')} a technical verdict. "
                f"{validated} VALIDATED. {counted(pass_runs, 'recent PASS', 'recent PASS')} and "
                f"{counted(fail_runs, 'FAIL', 'FAIL')}. Not a legal result. Untested is not failed."
            ),
            "href": "/assurance",
            "count": tested,
        },
        {
            "id": "action",
            "question": "What should I do next?",
            "answer": action[0]["detail"] if action else "No urgent gaps in these counts. Review freshness. Not a legal conclusion.",
            "href": action[0]["href"] if action else "/showcase",
            "count": len(action),
        },
    ]
    return {
        "questions": questions,
        "portfolio": {
            "count": len(systems),
            "primary_count": primary_count,
            "supporting_count": supporting,
            "labelled_synthetic": demo is not None,
            "demo_system_id": str(demo.id) if demo is not None else None,
            "display_name": SHOWCASE_DISPLAY_NAME if demo is not None else None,
            "organisation": SHOWCASE_ORG if demo is not None else None,
            "technical_identifier": DEMO_SYSTEM_NAME if demo is not None else None,
            "owners": sorted({item.owner for item in systems if item.owner}),
        },
        "threat_landscape": landscape,
        "threat_evidence_counts": {
            state: sum(1 for item in landscape if item["evidence_state"] == state) for state in EVIDENCE_STATES
        },
        "exposure": {
            "open_findings": len(open_findings),
            "high_or_critical_open": len(high),
            "by_severity": {
                "critical": sum(1 for item in open_findings if item.severity == "critical"),
                "high": sum(1 for item in open_findings if item.severity == "high"),
                "medium": sum(1 for item in open_findings if item.severity == "medium"),
                "low": sum(1 for item in open_findings if item.severity == "low"),
            },
        },
        "control_coverage": {
            "count": len(controls),
            "with_technical_verdict": tested,
            "validated": validated,
            "gaps": gaps,
            "untested": sum(1 for item in controls if not item.latest_verdict),
            "by_verdict": {
                "PASS": sum(1 for item in controls if item.latest_verdict == "PASS"),
                "FAIL": sum(1 for item in controls if item.latest_verdict == "FAIL"),
                "INCONCLUSIVE": sum(1 for item in controls if item.latest_verdict == "INCONCLUSIVE"),
                "NOT_ASSESSED": sum(1 for item in controls if not item.latest_verdict),
            },
        },
        "proven": {
            "validated": validated,
            "fresh_controls": int(freshness.get("fresh_controls") or 0),
            "recent_pass": pass_runs,
            "recent_fail": fail_runs,
        },
        "action_required": action,
        "journey": journey,
        "legal_compliance_claim": False,
        "runtime_firewall": False,
        "llm_is_verdict_authority": False,
    }


def threat_landscape(
    db: Session,
    *,
    controls: list[ControlRecord] | None = None,
    runs: list[AssuranceRunRecord] | None = None,
) -> list[dict]:
    threats = list(db.scalars(select(IntelThreat).order_by(IntelThreat.key)))
    control_ids = {item.id for item in controls} if controls is not None else None
    if runs:
        tested_control_ids = {item.control_id for item in runs if item.verdict}
    elif controls is not None:
        tested_control_ids = {item.id for item in controls if item.latest_verdict}
    else:
        tested_control_ids = {
            item.id for item in db.scalars(select(ControlRecord).where(ControlRecord.latest_verdict.is_not(None)))
        }
    landscape = []
    for threat in threats:
        techniques = list(db.scalars(select(IntelTechnique).where(IntelTechnique.threat_id == threat.id)))
        mapped = 0
        has_verdict = False
        capabilities = []
        for item in techniques:
            if item.affected_capability and item.affected_capability not in capabilities:
                capabilities.append(item.affected_capability)
            links = list(
                db.scalars(select(IntelTechniqueControl).where(IntelTechniqueControl.technique_id == item.id))
            )
            relevant = [
                link
                for link in links
                if control_ids is None or link.control_id in control_ids
            ]
            if relevant:
                mapped += 1
                if any(link.control_id in tested_control_ids for link in relevant):
                    has_verdict = True
        if has_verdict and threat.key in PROVEN_THREAT_KEYS:
            state = "tested"
        elif mapped:
            state = "mapped"
        elif techniques:
            state = "catalogued"
        else:
            state = "not_assessed"
        landscape.append(
            {
                "key": threat.key,
                "title": threat.title,
                "technique_count": len(techniques),
                "mapped_techniques": mapped,
                "capabilities": capabilities,
                "evidence_state": state,
                "tested": state == "tested",
                "informational_only": True,
                "href": f"/threats/{threat.key}",
            }
        )
    return landscape


def build_journey(db: Session, *, demo, findings, runs, controls) -> dict | None:
    if demo is None:
        return None
    ident = identity_for(demo)
    ctrl = next((item for item in controls if item.identifier == "CTRL-002"), None)
    system_findings = [item for item in findings if item.ai_system_id == demo.id]
    system_findings.sort(key=lambda item: item.created_at, reverse=True)
    fail = next((item for item in system_findings if item.verdict == "FAIL"), None)
    system_runs = [item for item in runs if item.ai_system_id == demo.id]
    fail_run = next((item for item in system_runs if item.scenario_key == "AUTH-01" and item.verdict == "FAIL"), None)
    remediations = []
    if system_findings:
        remediations = list(
            db.scalars(
                select(RemediationRecord)
                .where(RemediationRecord.finding_id.in_([item.id for item in system_findings]))
                .order_by(RemediationRecord.created_at.desc())
            )
        )
    finding_href = f"/findings/{fail.id}" if fail is not None else "/findings"
    control_href = f"/controls/{ctrl.id}" if ctrl is not None else "/controls"
    remediated = bool(remediations) or (fail is not None and fail.status in {"remediated", "resolved"})
    pass_run = next(
        (item for item in system_runs if item.verdict == "PASS" and item.parent_run_id),
        None,
    )
    retest_pass = fail is not None and fail.status == "resolved"
    if retest_pass:
        phase = "done"
        primary_href = "/exports"
        primary_label = "Download control matrix"
        story_headline = "The unauthorized cancel is now refused, with evidence."
        state_line = (
            "Re-tested: the assistant now refuses to cancel another customer's order, "
            "with evidence recorded."
        )
        current_step = None
    elif remediated:
        phase = "retest"
        primary_href = "/assurance"
        primary_label = "Confirm unauthorized cancel is blocked"
        story_headline = "A fix is in place. Confirm the cancel is now refused."
        state_line = (
            "An authorization check was added. "
            "The re-test confirming the cancel is now refused has not been run."
        )
        current_step = "Retest"
    elif fail is not None:
        phase = "remediate"
        primary_href = finding_href
        primary_label = "Enable authorization gateway"
        story_headline = "The support AI cancelled another customer's order."
        state_line = (
            "Tested: the assistant cancelled another customer's order with no authorization. "
            "That is an open finding."
        )
        current_step = "Finding"
    else:
        phase = "test"
        primary_href = "/assurance"
        primary_label = "Prove unauthorized order cancel"
        story_headline = "Can your support AI cancel another customer's order?"
        state_line = "Not tested yet. The assistant claims it checks permissions; that claim is unverified."
        current_step = "Test"
    phase_level = {"test": 0, "remediate": 1, "retest": 2, "done": 3}[phase]

    def step(label: str, href: str, detail: str, *, min_level: int) -> dict:
        if phase_level < min_level:
            return {"label": label, "href": "#", "detail": detail, "state": "locked"}
        if label == current_step:
            state = "current"
        elif phase_level > min_level or phase == "done":
            state = "done"
        else:
            state = "available"
        return {"label": label, "href": href, "detail": detail, "state": state}

    chain = [
        step("Threat", "/threats/tool_abuse", "Unauthorized tool execution", min_level=0),
        step("Technique", "/threats/tool_abuse/owasp_llm08", "OWASP LLM08 / ATLAS AML.T0048", min_level=0),
        step("AI system", f"/systems/{demo.id}", ident["display_name"], min_level=0),
        step("Control", control_href, "Tool authorization (CTRL-002)", min_level=0),
        step("Test", "/assurance", "Ask it to cancel a stranger's order (AUTH-01)", min_level=0),
        step(
            "Finding",
            finding_href if fail is not None else "#",
            "It cancelled the order" if fail else "Nothing has failed yet",
            min_level=1,
        ),
        step(
            "Remediation",
            finding_href if fail is not None else "#",
            humanize_action(remediations[0].action) if remediations else "Enable authorization gateway",
            min_level=1,
        ),
        step(
            "Retest",
            "/assurance" if remediated or retest_pass else "#",
            (
                "Cancel refused, legitimate requests still work (AUTH-02)"
                if retest_pass
                else "Run the same test again after the fix (AUTH-02)"
            ),
            min_level=2,
        ),
    ]
    return {
        "organisation": SHOWCASE_ORG,
        "ai_system": SHOWCASE_DISPLAY_NAME,
        "technical_identifier": DEMO_SYSTEM_NAME,
        "capability": "order support",
        "control": "CTRL-002",
        "threat": "Unauthorized Tool Execution / Excessive Agency",
        "test": "AUTH-01",
        "system_id": str(demo.id),
        "control_id": str(ctrl.id) if ctrl is not None else None,
        "finding_id": str(fail.id) if fail is not None else None,
        "primary_href": primary_href,
        "primary_label": primary_label,
        "story_headline": story_headline,
        "state_line": state_line,
        "phase": phase,
        "clicks_from_overview": 1,
        "latest_verdict": (
            pass_run.verdict
            if pass_run is not None
            else (fail_run.verdict if fail_run is not None else (system_runs[0].verdict if system_runs else "NOT_ASSESSED"))
        ),
        "retest_pass": retest_pass,
        "chain": chain,
        "labelled_synthetic": True,
        "legal_compliance_claim": False,
    }


def _action_queue(
    *,
    systems,
    high_count,
    gaps,
    untested,
    stale,
    pending_docs,
    demo=None,
    findings=None,
    journey=None,
) -> list[dict]:
    items: list[dict] = []
    if not systems:
        return [
            {
                "href": "/showcase",
                "label": "Load the labelled demo",
                "detail": "Zeros are honest. Start the guided demo to see unauthorized tool execution on CTRL-002.",
            }
        ]
    if journey and journey.get("primary_label"):
        items.append(
            {
                "href": journey["primary_href"],
                "label": journey["primary_label"],
                "detail": journey["primary_label"] + ". One next action on the Nordic Retail CTRL-002 chain.",
            }
        )
        return items[:1]
    if high_count:
        latest = findings[0] if findings else None
        items.append(
            {
                "href": f"/findings/{latest.id}" if latest is not None else "/findings",
                "label": "Enable authorization gateway"
                if latest is not None and getattr(latest, "verdict", None) == "FAIL"
                else "Open high-severity finding",
                "detail": f"{counted(high_count, 'high or critical finding', verb_one='needs', verb_many='need')} a decision with linked evidence.",
            }
        )
        return items[:1]
    if demo is not None and not high_count and not items:
        items.append(
            {
                "href": "/assurance",
                "label": "Prove unauthorized order cancel",
                "detail": "Confirm AUTH-01 on the labelled Customer Support AI Assistant.",
            }
        )
    if gaps and not items:
        items.append(
            {
                "href": "/controls",
                "label": "Control gaps",
                "detail": f"{counted(gaps, 'control')} in GAP_DETECTED with no PASS retest.",
            }
        )
    if stale:
        items.append(
            {
                "href": "/evidence",
                "label": "Stale evidence",
                "detail": f"{counted(stale, 'control')} outside the freshness window.",
            }
        )
    if untested and not high_count:
        items.append(
            {
                "href": "/assurance",
                "label": "Untested controls",
                "detail": f"{counted(untested, 'control', verb_one='has', verb_many='have')} no technical verdict yet. Untested is not FAIL.",
            }
        )
    if pending_docs:
        items.append(
            {
                "href": "/documents",
                "label": "Document review",
                "detail": f"{counted(pending_docs, 'extraction candidate')} awaiting a human.",
            }
        )
    if not items:
        items.append(
            {
                "href": "/showcase",
                "label": "No urgent gaps in these counts",
                "detail": "Review freshness and catalogs. This is not a legal conclusion.",
            }
        )
    return items[:1]
