from __future__ import annotations

import os
import uuid

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


def test_intelligence_explain_and_tasks(client: TestClient) -> None:
    status = client.get("/api/v1/intelligence/status")
    assert status.status_code == 200, status.text
    flags = status.json()
    assert flags["llm_is_verdict_authority"] is False
    assert flags["llm_may_authorize"] is False
    assert flags["legal_compliance_claim"] is False
    assert flags["runtime_firewall"] is False
    assert flags["secrets_persisted"] is False
    assert flags["llm_available"] is False
    assert "COMPLIANT" not in status.text

    boot = client.post("/api/v1/showcase/demo/bootstrap", headers=HEADERS, json={"confirm_execution": False})
    assert boot.status_code == 200, boot.text
    system_id = boot.json()["assurance"]["system_id"]

    explain = client.get(f"/api/v1/intelligence/explain?system_id={system_id}")
    assert explain.status_code == 200, explain.text
    body = explain.json()
    assert body["legal_compliance_claim"] is False
    assert body["llm_authored"] is False
    assert body["never_authorizes"] is True
    assert body["verdict_authority"] == "deterministic_policy"
    assert body["statements"]
    assert all(item.get("href") for item in body["statements"])
    assert "COMPLIANT" not in explain.text

    persisted = client.post(
        "/api/v1/intelligence/explain",
        headers=HEADERS,
        json={"system_id": system_id, "persist": True, "use_llm": True},
    )
    assert persisted.status_code == 200, persisted.text
    saved = persisted.json()
    assert saved["llm_authored"] is False
    assert saved["verdict_authority"] == "deterministic_policy"

    missing = client.post(
        "/api/v1/intelligence/tasks",
        headers=HEADERS,
        json={"task": "missing_governance", "system_id": system_id},
    )
    assert missing.status_code == 200, missing.text
    assert missing.json()["never_invents"] is True
    assert missing.json()["legal_compliance_claim"] is False

    correlate = client.post(
        "/api/v1/intelligence/tasks",
        headers=HEADERS,
        json={"task": "correlate_threats", "system_id": system_id},
    )
    assert correlate.status_code == 200, correlate.text
    assert correlate.json()["informational_only"] is True

    auditor = client.post(
        "/api/v1/intelligence/explain",
        headers={"X-Actor": "auditor", "X-Role": "auditor"},
        json={"system_id": system_id, "persist": True},
    )
    assert auditor.status_code == 403

    other = client.post(
        "/api/v1/systems",
        headers=HEADERS,
        json={"name": f"m13-other-{uuid.uuid4().hex[:8]}", "owner": "lab", "environment": "lab"},
    )
    assert other.status_code == 201, other.text
    other_id = other.json()["id"]
    isolated = client.get(f"/api/v1/intelligence/explain?system_id={other_id}")
    assert isolated.status_code == 200, isolated.text
    text = isolated.text
    assert "cancel_order" not in text
    assert isolated.json()["system_id"] == other_id
