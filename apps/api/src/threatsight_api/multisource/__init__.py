"""Multi-source exploitation intelligence (Phase 3D / 3D.1)."""

PARSER_VERSION = "multisource-v2"
RULESET_VERSION = "multisource-change-v2"

SOURCE_ROLES = frozenset(
    {
        "vendor_authority",
        "government_authority",
        "exploitation_observation",
        "media_discovery",
    }
)

EXPLOITATION_STATES = frozenset(
    {
        "not_reported",
        "media_reported",
        "researcher_observed",
        "vendor_confirmed",
        "government_catalogued",
        "conflicting",
        "withdrawn",
        "unknown",
    }
)

# Exploitation-relevant assertion types used for cluster state derivation.
# vendor_vulnerability_confirmed is retained as a vendor fact but is not an
# exploitation assertion.
EXPLOITATION_ASSERTION_TYPES = frozenset(
    {
        "vendor_exploitation_confirmed",
        "researcher_exploitation_observed",
        "researcher_catalogued",
        "media_exploitation_reported",
        "government_catalogued",
        "claim_withdrawn",
        "evidence_conflicting",
        # Legacy aliases retained for stored rows until repair remaps them.
        "exploitation_directly_observed",
        "exploitation_reported",
    }
)

ASSERTION_TYPES = frozenset(
    {
        "product_affected",
        "version_affected",
        "fixed_version",
        "prerequisite_required",
        "vendor_vulnerability_confirmed",
        "vendor_exploitation_confirmed",
        "researcher_exploitation_observed",
        "researcher_catalogued",
        "media_exploitation_reported",
        "government_catalogued",
        "remediation_available",
        "mitigation_available",
        "claim_withdrawn",
        "evidence_conflicting",
        # Legacy aliases (pre-3D.1-fix). Treated as vulnerability-only or mapped.
        "vendor_confirmed",
        "exploitation_directly_observed",
        "exploitation_reported",
    }
)
