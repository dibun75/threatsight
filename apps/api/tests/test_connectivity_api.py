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


def test_connectivity_ingest_and_isolation(client: TestClient) -> None:
    status = client.get("/api/v1/connectivity/status")
    assert status.status_code == 200, status.text
    flags = status.json()
    assert flags["runtime_firewall"] is False
    assert flags["passive_ingest"] is True
    assert flags["legal_compliance_claim"] is False
    assert "otel" in flags["source_kinds"]

    boot = client.post("/api/v1/showcase/demo/bootstrap", headers=HEADERS, json={"confirm_execution": False})
    assert boot.status_code == 200, boot.text
    system_id = boot.json()["assurance"]["system_id"]
    inventory = boot.json()["inventory"]
    assert inventory.get("agent_event_id")

    seeded = client.get("/api/v1/connectivity/events", params={"system_id": system_id})
    assert seeded.status_code == 200, seeded.text
    rows = seeded.json()
    assert any(item["tool_name"] == "cancel_order" and item["labelled_synthetic"] for item in rows)
    assert all(item["runtime_firewall"] is False for item in rows)

    created = client.post(
        "/api/v1/connectivity/events",
        headers=HEADERS,
        json={
            "ai_system_id": system_id,
            "source_kind": "sdk",
            "tool_name": "lookup_order",
            "authorization_context": {"authorized": True},
            "labelled_synthetic": True,
            "correlation_id": "m13-test-lookup",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["runtime_firewall"] is False

    refused = client.post(
        "/api/v1/connectivity/events",
        headers=HEADERS,
        json={"ai_system_id": system_id, "source_kind": "siem"},
    )
    assert refused.status_code == 400

    other = client.post(
        "/api/v1/systems",
        headers=HEADERS,
        json={"name": f"m13-connectivity-b-{uuid.uuid4().hex[:8]}", "owner": "lab", "environment": "lab"},
    )
    assert other.status_code == 201, other.text
    other_id = other.json()["id"]
    isolated = client.get("/api/v1/connectivity/events", params={"system_id": other_id})
    assert isolated.status_code == 200
    assert isolated.json() == []

    posture = client.get(f"/api/v1/systems/{system_id}/posture")
    assert posture.status_code == 200, posture.text
    graph = posture.json()
    assert graph["profile"]["purpose"]
    assert graph["traces"]
    assert "data_categories" in graph
    assert graph["legal_compliance_claim"] is False
    assert "UNKNOWN" in graph["missing_information"] or graph["capabilities"]
