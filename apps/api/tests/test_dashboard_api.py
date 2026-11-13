from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from threatsight_api.main import app

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}

pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_dashboard_never_claims_compliance_and_counts_real_rows(client: TestClient) -> None:
    emptyish = client.get("/api/v1/dashboard")
    assert emptyish.status_code == 200, emptyish.text
    body = emptyish.json()
    dumped = emptyish.text
    assert "COMPLIANT" not in dumped
    assert body["legal_compliance_claim"] is False
    assert body["synthetic_demo_labelled"] is True
    assert body["executive_summary"]["llm_authored"] is False
    assert body["evidence_freshness"]["states"] == ["FRESH", "STALE", "UNTESTED"]
    assert body["systems"]["provenance"]["legal_compliance_claim"] is False
    assert body["systems"]["provenance"]["enterprise_inventory"] is False
    assert body["findings"]["provenance"]["generated_by"] == "CTRL-002 validation tests"
    assert body["discovery"]["provenance"]["unrestricted_crawl"] is False
    assert body["frameworks"]["provenance"]["catalog_complete"] is False
    assert body["evidence"]["count"] >= 0
    assert body["documents"]["provenance"]["human_review"]
    assert set(body["controls"]["by_assurance_status"]) == {
        "VALIDATED",
        "PARTIALLY_VALIDATED",
        "GAP_DETECTED",
        "EVIDENCE_REQUIRED",
        "HUMAN_REVIEW_REQUIRED",
        "NOT_APPLICABLE",
    }

    boot = client.post("/api/v1/assurance/demo/bootstrap", headers={"X-Actor": "operator"})
    assert boot.status_code == 200, boot.text
    control_id = boot.json()["control_id"]
    system_id = boot.json()["system_id"]

    dash = client.get("/api/v1/dashboard").json()
    assert dash["synthetic_demo_present"] is True
    assert dash["systems"]["count"] >= 1
    assert dash["operations"]["legal_compliance_claim"] is False
    assert dash["operations"]["runtime_firewall"] is False
    assert [item["id"] for item in dash["operations"]["questions"]] == [
        "systems",
        "threats",
        "exposure",
        "controls",
        "proven",
        "action",
    ]
    assert "COMPLIANT" not in str(dash["operations"])
    assert dash["controls"]["count"] >= 1
    assert "Synthetic demo inventory" in dash["systems"]["provenance"]["data_origin"]
    assert dash["systems"]["provenance"]["enterprise_inventory"] is False
    assert "seeded demo data" in dash["controls"]["provenance"]["data_origin"]
    assert "technically tested" in dash["controls"]["provenance"]["validation"]

    filtered = client.get("/api/v1/controls", params={"q": "CTRL-002"})
    assert filtered.status_code == 200
    assert any(item["id"] == control_id for item in filtered.json())
    current_status = next(item["assurance_status"] for item in filtered.json() if item["id"] == control_id)
    by_status = client.get("/api/v1/controls", params={"assurance_status": current_status})
    assert any(item["id"] == control_id for item in by_status.json())

    fail = client.post(
        "/api/v1/assurance/runs",
        headers={"X-Actor": "operator"},
        json={"scenario_key": "AUTH-01", "confirm_execution": True},
    )
    assert fail.status_code == 201, fail.text
    after = client.get("/api/v1/dashboard").json()
    assert after["findings"]["count"] >= 1
    assert after["high_risk_findings"]
    assert after["recent_runs"]
    assert after["findings"]["provenance"]["data_origin"] == "M3 Assurance Engine"
    assert after["findings"]["provenance"]["generated_by"] == "CTRL-002 validation tests"
    assert after["findings"]["provenance"]["evidence_source"] in {"Available", "None recorded"}
    assert after["evidence"]["count"] >= 1
    assert after["evidence"]["provenance"]["legal_compliance_claim"] is False
    assert "COMPLIANT" not in str(after)

    posture = client.get(f"/api/v1/systems/{system_id}/posture")
    assert posture.status_code == 200, posture.text
    graph = posture.json()
    assert graph["legal_compliance_claim"] is False
    assert graph["system"]["id"] == system_id
    assert any(item["id"] == control_id for item in graph["controls"])
    assert graph["findings"]
    assert "missing_information" in graph
    assert graph["remediation_state"]["latest_verdict"] in {"FAIL", "PASS", "INCONCLUSIVE", "UNKNOWN"}

    by_control = client.get("/api/v1/findings", params={"control_id": control_id, "severity": "high"})
    assert by_control.status_code == 200
    assert by_control.json()

    rejected = client.get("/api/v1/controls", params={"assurance_status": "COMPLIANT"})
    assert rejected.status_code == 400
    assert "COMPLIANT" not in client.get("/api/v1/dashboard").text
