"""Phase 3E response workspace vocabulary and transition rules."""

from __future__ import annotations

MODES = frozenset({"assessment", "exercise", "incident_response"})
EVIDENCE_ASSESSMENTS = frozenset({"unreviewed", "suspected", "supported", "conflicting", "not_supported", "unknown"})
DECLARATIONS = frozenset({"not_declared", "suspected_incident", "confirmed_incident", "ruled_out"})
LIFECYCLES = frozenset({"draft", "monitoring", "assessing", "activated", "recovery_review", "closed", "cancelled"})

RESPONSE_ROLES = (
    "response_lead",
    "technical_lead",
    "service_owner",
    "evidence_coordinator",
    "communications_coordinator",
    "legal_regulatory_liaison",
    "executive_sponsor",
    "scribe",
)
CRITICAL_ROLES = frozenset({"response_lead", "technical_lead", "evidence_coordinator"})

TIMELINE_CATEGORIES = frozenset(
    {
        "intelligence_change",
        "assessment_update",
        "evidence_added",
        "action_update",
        "verification_result",
        "decision",
        "role_assignment",
        "declaration_change",
        "situation_report",
        "communication_draft",
        "closure_reopen",
    }
)

COMM_TEMPLATES = frozenset(
    {
        "executive_update",
        "internal_technical_update",
        "service_owner_request",
        "customer_stakeholder_holding",
        "regulator_notification_preparation",
    }
)

LIFECYCLE_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"monitoring", "assessing", "activated", "cancelled"}),
    "monitoring": frozenset({"assessing", "activated", "cancelled", "closed"}),
    "assessing": frozenset({"monitoring", "activated", "cancelled", "closed"}),
    "activated": frozenset({"recovery_review", "closed", "assessing"}),
    "recovery_review": frozenset({"activated", "closed"}),
    "closed": frozenset({"assessing"}),
    "cancelled": frozenset(),
}

DECLARATION_TRANSITIONS: dict[str, frozenset[str]] = {
    "not_declared": frozenset({"suspected_incident", "confirmed_incident", "ruled_out"}),
    "suspected_incident": frozenset({"confirmed_incident", "ruled_out", "not_declared"}),
    "confirmed_incident": frozenset({"ruled_out", "suspected_incident"}),
    "ruled_out": frozenset({"not_declared", "suspected_incident"}),
}

ADMIN_ROLES = frozenset({"workspace-admin", "platform-admin", "admin"})
WRITE_ROLES = ADMIN_ROLES | frozenset({"operator", "reviewer"})

DRAFT_NOT_SENT_LABEL = "Draft — not sent"
SYNTHETIC_EXERCISE_LABEL = "Synthetic exercise"
NOT_LEGAL_ADVICE = (
    "Not legal advice. Jurisdiction profiles organize evidence only; "
    "they do not determine legal applicability or regulatory obligations."
)

JURISDICTION_NIS2_NO_KEY = "nis2_norway_informational_v1"
