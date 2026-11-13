from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

from threatsight_api.main import app

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")
HEADERS = {"X-Actor": "operator"}
EVIDENCE_STATES = {"tested", "mapped", "catalogued", "not_assessed"}
POSTURES = {"ATTENTION REQUIRED", "REVIEW REQUIRED", "NO TESTED GAPS", "NOT ASSESSED"}


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_m14_showcase_reset_scope_and_nordic_retail_journey(client: TestClient) -> None:
    keeper = client.post(
        "/api/v1/systems",
        headers=HEADERS,
        json={
            "name": f"keep-m14-manual-{uuid.uuid4().hex[:8]}",
            "owner": "operator",
            "environment": "lab",
            "lifecycle": "draft",
        },
    )
    assert keeper.status_code == 201, keeper.text
    keeper_id = keeper.json()["id"]
    assert keeper.json()["record_origin"] == "manual"
    assert keeper.json()["display_name"] == keeper.json()["name"]

    denied = client.post(
        "/api/v1/showcase/demo/reset",
        headers={"X-Actor": "auditor", "X-Role": "auditor"},
        json={"reseed": True, "confirm_execution": False},
    )
    assert denied.status_code == 403

    reset = client.post(
        "/api/v1/showcase/demo/reset",
        headers=HEADERS,
        json={"reseed": True, "confirm_execution": False},
    )
    assert reset.status_code == 200, reset.text
    payload = reset.json()
    assert payload["legal_compliance_claim"] is False
    assert payload["unlabelled_records_untouched"] is True
    assert payload["origin_filter"] == "showcase"
    assert payload["reseeded"] is True
    assert payload["organisation"] == "Nordic Retail AS"
    assert payload["ai_system"] == "Customer Support AI Assistant"
    assert "COMPLIANT" not in reset.text
    demo_id = payload["bootstrap"]["assurance"]["system_id"]

    still = client.get(f"/api/v1/systems/{keeper_id}")
    assert still.status_code == 200
    assert still.json()["id"] == keeper_id
    assert still.json()["record_origin"] == "manual"

    demo = client.get(f"/api/v1/systems/{demo_id}").json()
    assert demo["name"] == "Order support demo"
    assert demo["display_name"] == "Customer Support AI Assistant"
    assert demo["organisation"] == "Nordic Retail AS"
    assert demo["technical_identifier"] == "Order support demo"
    assert demo["record_origin"] == "showcase"
    assert not demo["name"].startswith("agent-")

    dash = client.get("/api/v1/dashboard")
    assert dash.status_code == 200, dash.text
    body = dash.json()
    assert body["scope"] == "showcase"
    assert body["legal_compliance_claim"] is False
    assert body["systems"]["count"] >= 2
    assert body["systems"]["count"] < 10
    assert body["llm_available"] is False
    dumped = dash.text
    assert "COMPLIANT" not in dumped
    assert all(not (item.get("ai_system_name") or "").startswith("agent-") for item in body["high_risk_findings"])
    assert all(not (item.get("ai_system_display_name") or "").startswith("agent-") for item in body["high_risk_findings"])
    landscape = body["operations"]["threat_landscape"]
    assert landscape
    assert all(item["evidence_state"] in EVIDENCE_STATES for item in landscape)
    assert all(item["informational_only"] is True for item in landscape)
    assert body["operations"]["threat_evidence_counts"]["tested"] == 0
    journey = body["operations"]["journey"]
    assert journey["ai_system"] == "Customer Support AI Assistant"
    assert journey["organisation"] == "Nordic Retail AS"
    assert journey["clicks_from_overview"] <= 3
    assert [step["label"] for step in journey["chain"]] == [
        "Threat",
        "Technique",
        "AI system",
        "Control",
        "Test",
        "Finding",
        "Remediation",
        "Retest",
    ]

    all_dash = client.get("/api/v1/dashboard", params={"scope": "all"}).json()
    assert all_dash["scope"] == "all"
    assert all_dash["systems"]["count"] >= body["systems"]["count"]

    posture = client.get(f"/api/v1/systems/{demo['id']}/posture")
    assert posture.status_code == 200, posture.text
    graph = posture.json()
    assert graph["system"]["display_name"] == "Customer Support AI Assistant"
    assert graph["posture_summary"] in POSTURES
    assert graph["posture_summary"] != "COMPLIANT"
    assert "COMPLIANT" not in posture.text

    executed = client.post(
        "/api/v1/assurance/runs",
        headers=HEADERS,
        json={"scenario_key": "AUTH-01", "confirm_execution": True},
    )
    assert executed.status_code == 201, executed.text
    assert executed.json()["verdict"] == "FAIL"

    after = client.get("/api/v1/dashboard").json()
    assert after["high_risk_findings"]
    assert after["operations"]["journey"]["finding_id"]
    assert after["operations"]["journey"]["clicks_from_overview"] <= 3
    assert after["operations"]["journey"]["primary_href"].startswith("/findings/")
    finding_id = after["operations"]["journey"]["finding_id"]
    finding = client.get(f"/api/v1/findings/{finding_id}")
    assert finding.status_code == 200, finding.text
    assert finding.json()["ai_system_display_name"] == "Customer Support AI Assistant"
    assert "COMPLIANT" not in finding.text

    attention = client.get(f"/api/v1/systems/{demo['id']}/posture").json()
    assert attention["posture_summary"] == "ATTENTION REQUIRED"

    threats = client.get("/api/v1/threats").json()
    assert all(item["evidence_state"] in EVIDENCE_STATES for item in threats)
    tested = [item for item in threats if item["evidence_state"] == "tested"]
    assert tested
    assert {item["key"] for item in tested} == {"tool_abuse"}
