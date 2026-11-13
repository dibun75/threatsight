from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from threatsight_api.main import app

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}

pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")
HEADERS = {"X-Actor": "operator"}


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_showcase_bootstrap_matrix_and_summary(client: TestClient) -> None:
    status = client.get("/api/v1/showcase/status")
    assert status.status_code == 200, status.text
    flags = status.json()
    assert flags["legal_compliance_claim"] is False
    assert flags["llm_authors_executive_summary"] is False
    assert flags["autonomous_attack"] is False
    assert flags["exploitation_engine"] is False
    assert flags["unrestricted_crawl"] is False
    assert flags["framework_catalog_complete"] is False
    assert flags["intel_catalog_complete"] is False
    assert flags["confirm_execution_required_for_auth01"] is True
    assert flags["walkthrough"]
    assert flags["guided_story"][0]["id"] == "system"
    assert flags["scenario"]["company"] == "Nordic Retail AS"
    assert flags["scenario"]["labelled_synthetic"] is True
    assert flags["scenario"]["legal_compliance_claim"] is False
    assert "COMPLIANT" not in status.text

    denied = client.post(
        "/api/v1/showcase/demo/bootstrap",
        headers={"X-Actor": "auditor", "X-Role": "auditor"},
        json={"confirm_execution": False},
    )
    assert denied.status_code == 403

    boot = client.post("/api/v1/showcase/demo/bootstrap", headers=HEADERS, json={"confirm_execution": False})
    assert boot.status_code == 200, boot.text
    body = boot.json()
    assert body["legal_compliance_claim"] is False
    assert body["synthetic_demo_labelled"] is True
    assert body["executed_auth01"] is False
    assert body["inventory"]["synthetic_demo_labelled"] is True
    assert body["inventory"]["knowledge_system_id"]
    assert body["inventory"]["attestation_evidence_id"]
    assert body["assurance"]["control_id"]
    assert body["frameworks"]["catalog_complete"] is False
    assert body["threats"]["autonomous_attack"] is False
    assert body["discovery"]["synthetic"] is True
    assert body["scenario"]["company"] == "Nordic Retail AS"
    assert body["scenario"]["inventory_name"] == "Order support demo"
    assert body["scenario"]["legal_compliance_claim"] is False
    control_id = body["assurance"]["control_id"]

    dash = client.get("/api/v1/dashboard")
    assert dash.status_code == 200, dash.text
    posture = dash.json()
    assert posture["legal_compliance_claim"] is False
    assert posture["systems"]["count"] >= 2
    assert posture["executive_summary"]["llm_authored"] is False
    assert posture["executive_summary"]["legal_compliance_claim"] is False
    assert posture["evidence_freshness"]["states"] == ["FRESH", "STALE", "UNTESTED"]
    assert "COMPLIANT" not in dash.text

    assurance = client.get(f"/api/v1/controls/{control_id}/assurance")
    assert assurance.status_code == 200, assurance.text
    view = assurance.json()
    assert view["freshness"] in {"FRESH", "STALE", "UNTESTED"}
    assert view["legal_compliance_claim"] is False

    matrix = client.get("/api/v1/exports/control-matrix.json")
    assert matrix.status_code == 200, matrix.text
    payload = matrix.json()
    assert payload["kind"] == "control_matrix"
    assert payload["legal_compliance_claim"] is False
    assert payload["llm_authored"] is False
    assert payload["item_count"] >= 1
    row = next(item for item in payload["items"] if item["control"] == "CTRL-002")
    assert row["freshness"] in {"FRESH", "STALE", "UNTESTED"}
    assert row["requirement"]
    assert row["framework"]
    assert "COMPLIANT" not in matrix.text

    csv_body = client.get("/api/v1/exports/control-matrix.csv")
    assert csv_body.status_code == 200
    header = csv_body.text.splitlines()[0]
    assert header == "control,requirement,test,result,evidence,owner,framework,freshness"

    executed = client.post("/api/v1/showcase/demo/bootstrap", headers=HEADERS, json={"confirm_execution": True})
    assert executed.status_code == 200, executed.text
    result = executed.json()
    assert result["executed_auth01"] is True
    assert result["verdict"] == "FAIL"
    assert result["legal_compliance_claim"] is False

    after = client.get("/api/v1/exports/control-matrix.json").json()
    ctrl = next(item for item in after["items"] if item["control"] == "CTRL-002")
    assert ctrl["test"] == "AUTH-01"
    assert ctrl["result"] == "FAIL"
    assert ctrl["evidence"]
    assert ctrl["freshness"] == "FRESH"
    assert "COMPLIANT" not in str(after)
