"""Maps an assessment result to the EU AI Act articles it can give evidence for.

This is evidence, not a compliance verdict. Whether a system meets the Act depends on its risk
classification, its documentation, data governance and human oversight, none of which an agent
test can establish. What a test run can supply is a record of how the agent behaved under attack,
which a provider can use in their technical documentation for these articles of Regulation (EU)
2024/1689:

- Article 15 (accuracy, robustness and cybersecurity), mainly 15(1) and 15(5): resilience against
  attempts by unauthorised third parties to alter use, outputs or performance by exploiting
  vulnerabilities, including AI-specific ones.
- Article 9 (risk management system): identifying foreseeable risks and testing against defined
  metrics before the system is put into service.
- Article 12 (record-keeping): automatic recording of events for traceability.
- Article 14 (human oversight), only where a high-risk action was held for a named person.

The mapping is the author's reading of the Act's text, not an official or legal one. The Digital
Omnibus on AI moved the application dates of the high-risk obligations (stand-alone Annex III
systems to 2 December 2027, products under Annex I to 2 August 2028 as reported by law firms in
mid-2026); check the Official Journal for the dates that apply to a given system.
"""
from __future__ import annotations

from typing import Any

DISCLAIMER = (
    "This is evidence a provider can use for these articles, not a statement that the system complies with the EU AI Act. "
    "Compliance also depends on risk classification, documentation, data governance and human oversight, which this test does not cover."
)


def _item(article: str, title: str, strength: str, evidence: str) -> dict[str, str]:
    return {"article": article, "title": title, "strength": strength, "evidence": evidence}


def ai_act_evidence(run: dict[str, Any]) -> dict[str, Any]:
    """Evidence items for one run record. `strength` is "supports", "gap" (the test found a weakness
    to fix before the evidence is useful) or "none" (the attack was not tried, so nothing was shown)."""
    results = run.get("runs") or []
    verdicts = [r["verdict"]["verdict"] for r in results]
    final = verdicts[-1] if verdicts else "INCONCLUSIVE"
    reasons = {r["verdict"]["reason_code"] for r in results}
    held = "HELD_FOR_APPROVAL" in reasons or any(a.get("decision") for a in run.get("approvals", []))
    retested = len(verdicts) == 2 and verdicts[0] == "FAIL" and verdicts[1] == "PASS"
    ev = run.get("evidence") or {}

    if final == "PASS":
        a15 = _item("Article 15(5)", "Resilience against unauthorised third parties", "supports",
                    "The agent was attacked with a hostile instruction and no harmful action took place"
                    + (", after a guardrail fixed a gap the first run exposed." if retested else "."))
    elif final == "FAIL":
        a15 = _item("Article 15(5)", "Resilience against unauthorised third parties", "gap",
                    "The attack caused a harmful action. This is a weakness to fix and test again before it can count as evidence of robustness.")
    else:
        a15 = _item("Article 15(5)", "Resilience against unauthorised third parties", "none",
                    "The agent never tried the hostile action, so this run shows nothing about its resilience.")

    items = [a15]
    if verdicts:
        items.append(_item("Article 9", "Risk management system", "supports",
                           "A foreseeable misuse risk was identified, tested with a defined pass or fail check, and"
                           + (" re-tested after a control was added." if len(verdicts) > 1 else " given a recorded result.")))
    if ev.get("records"):
        items.append(_item("Article 12", "Record-keeping", "supports",
                           f"Each step was written to a linked record of {ev['records']} entries"
                           + (", signed" if ev.get("signed") else "") + ", so the run can be traced and checked afterwards."))
    if held:
        items.append(_item("Article 14", "Human oversight", "supports",
                           "A high-risk action was paused until a named person approved or rejected it."))
    return {"regulation": "Regulation (EU) 2024/1689", "items": items, "disclaimer": DISCLAIMER}
