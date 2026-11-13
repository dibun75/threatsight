"""P2-12 analysis vocabulary. States are rule outcomes, not safety claims."""

from __future__ import annotations

RULESET_VERSION = "p2-12.v1"

CATEGORIES: tuple[str, ...] = (
    "internet_exposure_candidate",
    "management_plane_candidate",
    "privileged_identity_path",
    "cross_domain_service_path",
    "contradiction_gap",
)

STATES: tuple[str, ...] = (
    "supported_candidate",
    "unknown",
    "conflicting",
    "unsupported",
    "not_evaluated",
)

RUN_STATUSES: tuple[str, ...] = ("building", "completed", "failed", "cancelled")

GLOBAL_LIMITATIONS: tuple[str, ...] = (
    "not_packet_delivery",
    "not_exploitability",
    "not_compromise",
    "not_control_effectiveness",
    "not_compliance",
    "not_threat_relevance",
    "absence_is_not_safety",
)


def sql_in(column: str, values: tuple[str, ...]) -> str:
    quoted = ",".join(f"'{item}'" for item in values)
    return f"{column} IN ({quoted})"
