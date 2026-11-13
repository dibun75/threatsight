"""Bounded readiness vocabulary. Generic passed is forbidden."""

from __future__ import annotations

RECOMMENDATION_STATES = frozenset(
    {"candidate", "needs_more_data", "not_supported", "superseded", "dismissed", "approved"}
)
REQUEST_TYPES = frozenset({"read_only_connector", "manual_evidence", "unsupported_live_required"})
REQUEST_STATUSES = frozenset(
    {
        "pending_approval",
        "approved",
        "queued",
        "running",
        "succeeded",
        "failed",
        "cancelled",
        "dismissed",
        "superseded",
        "expired",
    }
)
RESULT_OUTCOMES = frozenset(
    {
        "observed",
        "configured_not_observed",
        "passed_by_defined_check",
        "failed_by_defined_check",
        "unknown",
        "conflicting",
        "unsupported",
        "collection_failed",
    }
)
DECISION_OUTCOMES = frozenset(
    {"accepted", "remediation_required", "not_applicable", "needs_more_data", "risk_accepted", "superseded"}
)
APPROVE_ROLES = frozenset({"workspace-admin", "platform-admin", "admin"})
REVIEW_ROLES = frozenset({"operator", "reviewer", "workspace-admin", "platform-admin", "admin"})

MEANINGS = {
    "candidate": "ThreatSight recommends reviewing this control. It is not a failure.",
    "configured_not_observed": "Configuration was collected. Effectiveness was not observed.",
    "passed_by_defined_check": "The named allowlisted check returned its pass condition. This is not control effectiveness.",
    "failed_by_defined_check": "The named allowlisted check returned its fail condition. This is not compromise.",
    "accepted": "An authorized person accepted the recorded result. This is not a compliance certificate.",
    "risk_accepted": "An authorized person recorded acceptance of residual uncertainty. This is not safety.",
}
