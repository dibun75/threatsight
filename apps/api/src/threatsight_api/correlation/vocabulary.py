"""P2-13 correlation vocabulary. A match is not an incident."""

from __future__ import annotations

RULESET_VERSION = "p2-13.v1"

STATES: tuple[str, ...] = (
    "confirmed_identifier_match",
    "version_supported_candidate",
    "possible_match",
    "unknown",
    "conflicting",
    "not_applicable_by_evidence",
)

REVIEW_STATES: tuple[str, ...] = (
    "unreviewed",
    "accepted_relevant",
    "not_applicable",
    "needs_more_data",
    "suppressed_until",
)

RUN_STATUSES: tuple[str, ...] = ("building", "completed", "failed", "cancelled")

GLOBAL_LIMITATIONS: tuple[str, ...] = (
    "not_compromise",
    "not_exploitability",
    "not_packet_delivery",
    "not_control_failure",
    "not_remediation",
    "not_attacker_origin",
    "absence_is_not_safety",
)


def sql_in(column: str, values: tuple[str, ...]) -> str:
    quoted = ",".join(f"'{item}'" for item in values)
    return f"{column} IN ({quoted})"
