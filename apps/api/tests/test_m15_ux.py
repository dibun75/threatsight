from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from threatsight_api.main import app
from threatsight_api.services.copy import counted, humanize_action
from threatsight_api.services.dashboard import posture_summary
from threatsight_api.services.operations import technical_gaps

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
HEADERS = {"X-Actor": "operator"}


def test_copy_humanizes_gateway_action_and_grammar() -> None:
    assert humanize_action("enable_gateway_authorization") == "Authorization gateway enabled"
    assert counted(1, "control", verb_one="has", verb_many="have") == "1 control has"
    assert counted(2, "finding", verb_one="needs", verb_many="need") == "2 findings need"
    assert counted(1, "high or critical finding", verb_one="needs", verb_many="need") == (
        "1 high or critical finding needs"
    )
    assert "COMPLIANT" not in humanize_action("enable_gateway_authorization")


def test_technical_gaps_ignore_pass_retest() -> None:
    open_gap = SimpleNamespace(assurance_status="GAP_DETECTED", latest_verdict="FAIL")
    closed = SimpleNamespace(assurance_status="GAP_DETECTED", latest_verdict="PASS")
    validated = SimpleNamespace(assurance_status="VALIDATED", latest_verdict="PASS")
    assert technical_gaps([open_gap, closed, validated]) == 1


def test_posture_uses_open_status_and_pending_retest() -> None:
    open_high = SimpleNamespace(status="open", severity="high")
    remediated = SimpleNamespace(status="remediated", severity="high")
    resolved = SimpleNamespace(status="resolved", severity="high")
    pass_run = SimpleNamespace(verdict="PASS")
    fail_run = SimpleNamespace(verdict="FAIL")
    leftover_gap = SimpleNamespace(assurance_status="GAP_DETECTED", latest_verdict="PASS")
    assert posture_summary(findings=[open_high], runs=[fail_run], missing=[], controls=[]) == "ATTENTION REQUIRED"
    assert posture_summary(findings=[remediated], runs=[pass_run], missing=[], controls=[]) == "ATTENTION REQUIRED"
    assert (
        posture_summary(findings=[resolved], runs=[pass_run], missing=[], controls=[leftover_gap]) == "NO TESTED GAPS"
    )
    assert posture_summary(findings=[], runs=[], missing=[], controls=[]) == "NOT ASSESSED"


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_m15_showcase_scope_journey_and_truthful_close() -> None:
    with TestClient(app) as client:
        reset = client.post(
            "/api/v1/showcase/demo/reset",
            headers=HEADERS,
            json={"reseed": True, "confirm_execution": False},
        )
        assert reset.status_code == 200, reset.text
        demo_id = reset.json()["bootstrap"]["assurance"]["system_id"]

        systems = client.get("/api/v1/systems", params={"scope": "showcase"}).json()
        assert systems
        assert all(item["display_name"] != "Order support demo" for item in systems)
        assert any(item["display_name"] == "Customer Support AI Assistant" for item in systems)
        assert all(not (item.get("name") or "").startswith("agent-") for item in systems)

        controls = client.get("/api/v1/controls", params={"scope": "showcase"}).json()
        assert any(item["identifier"] == "CTRL-002" for item in controls)

        documents = client.get("/api/v1/documents", params={"scope": "showcase"}).json()
        assert documents == []

        dash = client.get("/api/v1/dashboard").json()
        journey = dash["operations"]["journey"]
        assert journey["phase"] == "test"
        assert journey["primary_label"] == "Prove unauthorized order cancel"
        assert journey["story_headline"]
        assert journey["state_line"]
        assert journey["primary_href"] == "/assurance"
        locked = [step["label"] for step in journey["chain"] if step["state"] == "locked"]
        assert locked == ["Finding", "Remediation", "Retest"]
        assert dash["operations"]["action_required"][0]["label"] == "Prove unauthorized order cancel"
        assert len(dash["operations"]["action_required"]) == 1
        assert dash["operations"]["threat_evidence_counts"]["tested"] == 0
        assert "COMPLIANT" not in str(dash)

        fail = client.post(
            "/api/v1/assurance/runs",
            headers=HEADERS,
            json={"scenario_key": "AUTH-01", "confirm_execution": True},
        )
        assert fail.status_code == 201, fail.text
        assert fail.json()["verdict"] == "FAIL"
        finding_id = fail.json()["finding_id"]

        after_fail = client.get("/api/v1/dashboard").json()
        assert after_fail["operations"]["journey"]["phase"] == "remediate"
        assert after_fail["operations"]["journey"]["primary_label"] == "Enable authorization gateway"
        assert after_fail["operations"]["journey"]["primary_href"].startswith("/findings/")
        assert after_fail["high_risk_findings"]
        retest_step = next(item for item in after_fail["operations"]["journey"]["chain"] if item["label"] == "Retest")
        assert retest_step["state"] == "locked"
        tested = [item["key"] for item in after_fail["operations"]["threat_landscape"] if item["evidence_state"] == "tested"]
        assert tested == ["tool_abuse"]

        evidence = client.get("/api/v1/evidence", params={"scope": "showcase"}).json()
        hashed = [item for item in evidence if item.get("integrity_hash") or item.get("evidence_type") == "test_artifact"]
        assert hashed
        assert evidence[0]["id"] == hashed[0]["id"]

        premature = client.post(
            "/api/v1/assurance/runs",
            headers=HEADERS,
            json={"scenario_key": "AUTH-02", "confirm_execution": True},
        )
        assert premature.status_code == 201, premature.text
        assert premature.json()["verdict"] == "PASS"
        still_open = client.get(f"/api/v1/findings/{finding_id}").json()
        assert still_open["status"] == "open"
        assert client.get("/api/v1/dashboard").json()["operations"]["journey"]["phase"] == "remediate"

        remediated = client.post(f"/api/v1/findings/{finding_id}/remediate", headers=HEADERS)
        assert remediated.status_code == 201, remediated.text
        assert remediated.json()["action"] == "enable_gateway_authorization"

        after_fix = client.get("/api/v1/dashboard").json()
        assert after_fix["operations"]["journey"]["phase"] == "retest"
        assert after_fix["operations"]["journey"]["primary_label"] == "Confirm unauthorized cancel is blocked"
        assert after_fix["high_risk_findings"] == []
        assert after_fix["findings"]["open"] == 0
        attention = client.get(f"/api/v1/systems/{demo_id}/posture").json()
        assert attention["posture_summary"] == "ATTENTION REQUIRED"

        retest = client.post(
            "/api/v1/assurance/runs",
            headers=HEADERS,
            json={
                "scenario_key": "AUTH-02",
                "confirm_execution": True,
                "parent_run_id": fail.json()["id"],
            },
        )
        assert retest.status_code == 201, retest.text
        assert retest.json()["verdict"] == "PASS"
        assert retest.json()["parent_run_id"] == fail.json()["id"]

        closed = client.get(f"/api/v1/findings/{finding_id}").json()
        assert closed["status"] == "resolved"
        control = client.get(f"/api/v1/controls/{fail.json()['control_id']}").json()
        assert control["latest_verdict"] == "PASS"

        done = client.get("/api/v1/dashboard").json()
        assert done["operations"]["journey"]["phase"] == "done"
        assert done["operations"]["journey"]["primary_label"] == "Download control matrix"
        assert done["operations"]["journey"]["retest_pass"] is True
        assert done["high_risk_findings"] == []
        assert done["operations"]["control_coverage"]["gaps"] == 0
        assert "1 control has" in str(done["executive_summary"]["sentences"]) or any(
            "has a technical verdict" in sentence or "have a technical verdict" in sentence
            for sentence in done["executive_summary"]["sentences"]
        )
        tested_after = [
            item["key"] for item in done["operations"]["threat_landscape"] if item["evidence_state"] == "tested"
        ]
        assert tested_after == ["tool_abuse"]
        posture = client.get(f"/api/v1/systems/{demo_id}/posture").json()
        assert posture["posture_summary"] != "ATTENTION REQUIRED"
        assert posture["posture_summary"] in {"NO TESTED GAPS", "REVIEW REQUIRED"}
        assert posture["posture_summary"] != "COMPLIANT"
        assert "COMPLIANT" not in str(done)
        matrix = client.get("/api/v1/exports/control-matrix.json", params={"scope": "showcase"}).json()
        assert matrix["legal_compliance_claim"] is False
        assert any(item["control"] == "CTRL-002" for item in matrix["items"])
