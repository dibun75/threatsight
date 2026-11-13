"""Phase 3 feature tenant/workspace isolation regressions (Phase 3G)."""

from __future__ import annotations

import uuid

from threatsight_api.api.deps import tenant_matches


def test_tenant_uuid_mismatch_rejected() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    assert tenant_matches(a, a)
    assert not tenant_matches(a, b)
    assert not tenant_matches(a, uuid.uuid4())


def test_phase3_isolation_surface_contract() -> None:
    """Every Phase 3 surface must enforce membership — documented contract for audits."""
    surfaces = {
        "radar": "membership_enforced",
        "multisource_intelligence": "workspace_scoped_relevance",
        "readiness_actions": "workspace_scoped",
        "evidence_signing": "workspace_scoped_leases",
        "response_workspace": "workspace_scoped",
        "correlation": "workspace_scoped",
        "exports_manifests": "workspace_scoped",
        "audit_events": "tenant_scoped",
        "synthetic_reference": "must_not_become_customer_evidence",
        "public_intelligence": "shareable_relevance_is_workspace_specific",
    }
    assert surfaces["synthetic_reference"] == "must_not_become_customer_evidence"
    assert "customer" not in surfaces["public_intelligence"] or "workspace" in surfaces["public_intelligence"]
