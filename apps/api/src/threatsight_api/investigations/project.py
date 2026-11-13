"""Assemble stored investigation steps. This module does not query or infer relationships."""

from __future__ import annotations

CLASSIFICATION = {
    "confirmed_identifier_match": "Identifier match",
    "version_supported_candidate": "Version-supported candidate",
    "possible_match": "Possible match",
    "unknown": "Unknown",
    "conflicting": "Conflicting",
    "not_applicable_by_evidence": "Not applicable by evidence",
}

EVIDENCE_STATE = {
    "observed": "Observed",
    "configured": "Configured",
    "inferred": "Inferred",
    "manual": "Manual",
    "unknown": "Unknown",
    "conflicting": "Conflicting",
    "unsupported": "Unsupported",
}


def classification(state: str) -> str:
    return CLASSIFICATION.get(state, "Unknown")


def evidence_state(mode: str) -> str:
    return EVIDENCE_STATE.get(mode, "Unknown")


def path_steps(edge_keys: list[str], edges: dict[str, dict]) -> list[dict]:
    steps = []
    for key in edge_keys[:12]:
        edge = edges.get(key)
        if edge is None:
            steps.append(_missing(key))
            continue
        steps.append(
            {
                "from": edge["from_label"],
                "relationship": edge["edge_type"],
                "to": edge["to_label"],
                "evidence_state": evidence_state(str(edge["evidence_mode"])),
                "source": edge["source"],
                "freshness": edge["freshness"],
                "collected_at": edge["collected_at"],
                "maturity": edge["maturity"],
                "confidence": edge["confidence"],
                "limitation": "A configured or inferred step is not proven packet delivery or effective reachability.",
                "edge_id": edge["id"],
            }
        )
    if steps:
        return steps
    return [_missing(None)]


def _missing(key: str | None) -> dict:
    limitation = "No stored edge supports this step. Absence is not proof that no relationship exists."
    if key:
        limitation = "The stored edge key is not in this snapshot. Absence is not proof that no relationship exists."
    return {
        "from": "Not recorded",
        "relationship": "unknown",
        "to": "Not recorded",
        "evidence_state": "Unknown",
        "source": "not recorded",
        "freshness": "untested",
        "collected_at": None,
        "maturity": "unknown",
        "confidence": "unknown",
        "limitation": limitation,
        "edge_id": None,
    }
