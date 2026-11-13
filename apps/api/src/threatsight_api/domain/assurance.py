from threatsight_api.domain.enums import AssuranceStatus

FORBIDDEN_ASSURANCE_LABELS = frozenset(
    {
        "COMPLIANT",
        "NON_COMPLIANT",
        "compliant",
        "non-compliant",
        "compliant_boolean",
        "legal_compliant",
    }
)


def assert_assurance_status(value: str) -> AssuranceStatus:
    if value in FORBIDDEN_ASSURANCE_LABELS:
        raise ValueError(
            "ThreatSight does not record legal compliance as a status. "
            "Use VALIDATED, PARTIALLY_VALIDATED, GAP_DETECTED, EVIDENCE_REQUIRED, "
            "HUMAN_REVIEW_REQUIRED, or NOT_APPLICABLE."
        )
    try:
        return AssuranceStatus(value)
    except ValueError as exc:
        raise ValueError(f"Unknown assurance status: {value}") from exc
