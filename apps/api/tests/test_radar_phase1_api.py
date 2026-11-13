from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.main import app
from threatsight_api.persistence.models import (
    Workspace,
    WorkspaceMembership,
)
from threatsight_api.persistence.session import get_engine

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _ensure_auditor() -> None:
    with Session(get_engine()) as session:
        workspace = session.scalar(select(Workspace).where(Workspace.key == "default"))
        membership = session.scalar(
            select(WorkspaceMembership).where(
                WorkspaceMembership.workspace_id == workspace.id,
                WorkspaceMembership.subject == "phase1-auditor",
            )
        )
        if membership is None:
            session.add(
                WorkspaceMembership(
                    workspace_id=workspace.id,
                    subject="phase1-auditor",
                    role="auditor",
                )
            )
            session.commit()


def test_filter_bounds_and_geographic_semantics(client: TestClient) -> None:
    headers = {"X-Actor": "operator"}
    bounded = client.get(
        "/api/v1/radar/events?country=NO&geography=authority&limit=5&page=1"
        "&sort=relevance&direction=desc",
        headers=headers,
    )
    assert bounded.status_code == 200, bounded.text
    assert bounded.json()["limit"] == 5
    assert bounded.json()["page"] == 1
    assert "total" in bounded.json()
    assert client.get("/api/v1/radar/events?limit=101", headers=headers).status_code == 422
    assert client.get("/api/v1/radar/events?sort=title", headers=headers).status_code == 422


def test_saved_view_crud_is_workspace_owned_and_auditor_read_only(
    client: TestClient,
) -> None:
    headers = {"X-Actor": "operator"}
    name = f"Nordic critical {uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/radar/saved-views",
        headers=headers,
        json={
            "name": name,
            "filters": {
                "country": "NO",
                "geography": "authority",
                "relevance": "critical",
                "limit": 25,
            },
        },
    )
    assert created.status_code == 201, created.text
    view_id = created.json()["id"]
    assert client.get(
        f"/api/v1/radar/saved-views/{view_id}", headers=headers
    ).status_code == 200
    updated = client.put(
        f"/api/v1/radar/saved-views/{view_id}",
        headers=headers,
        json={"name": f"{name} updated", "filters": {"source": "nsm-rss"}},
    )
    assert updated.status_code == 200, updated.text

    _ensure_auditor()
    auditor = {"X-Actor": "phase1-auditor", "X-Role": "admin"}
    assert client.get("/api/v1/radar/saved-views", headers=auditor).status_code == 200
    denied = client.put(
        f"/api/v1/radar/saved-views/{view_id}",
        headers=auditor,
        json={"name": "spoofed", "filters": {}},
    )
    assert denied.status_code == 403

    assert client.delete(
        f"/api/v1/radar/saved-views/{view_id}", headers=headers
    ).status_code == 204


def test_triage_and_manual_link_do_not_mutate_assurance(client: TestClient) -> None:
    headers = {"X-Actor": "operator"}
    feed = client.get("/api/v1/radar/events?limit=1", headers=headers)
    assert feed.status_code == 200, feed.text
    if not feed.json()["items"]:
        pytest.skip("preserved Phase 0 database has no Radar events")
    event_id = feed.json()["items"][0]["id"]
    triage = client.put(
        f"/api/v1/radar/triage/event/{event_id}",
        headers=headers,
        json={
            "status": "reviewing",
            "priority": "high",
            "owner": "security-operations",
            "rationale": "Validate applicability against the asset inventory.",
        },
    )
    assert triage.status_code == 200, triage.text

    resources = client.get("/api/v1/radar/resources", headers=headers)
    assert resources.status_code == 200, resources.text
    if not resources.json():
        pytest.skip("preserved database has no workspace-bound readiness resources")
    target = resources.json()[0]
    linked = client.post(
        f"/api/v1/radar/links/event/{event_id}",
        headers=headers,
        json={
            "target_type": target["type"],
            "target_id": target["id"],
            "reason": "Analyst context only; validate control coverage.",
            "provenance": "Manual Phase 1 test",
            "limitations": ["Does not establish exposure, control effectiveness, or compliance."],
        },
    )
    assert linked.status_code in {201, 409}, linked.text
    event = client.get("/api/v1/radar/events?limit=100", headers=headers)
    matched = next(item for item in event.json()["items"] if item["id"] == event_id)
    assert matched["exposure_confirmed"] is False
    assert matched["legal_compliance_claim"] is False


def test_cross_workspace_workflow_id_is_not_visible(client: TestClient) -> None:
    default_headers = {"X-Actor": "operator"}
    created = client.post(
        "/api/v1/radar/saved-views",
        headers=default_headers,
        json={"name": f"isolation-{uuid.uuid4().hex[:8]}", "filters": {}},
    )
    assert created.status_code == 201, created.text
    view_id = created.json()["id"]
    workspace_key = f"phase1-{uuid.uuid4().hex[:8]}"
    subject = f"isolated-{uuid.uuid4().hex[:8]}"
    with Session(get_engine()) as session:
        workspace = Workspace(key=workspace_key, name="Phase 1 isolation", status="active")
        session.add(workspace)
        session.flush()
        session.add(
            WorkspaceMembership(
                workspace_id=workspace.id,
                subject=subject,
                role="operator",
            )
        )
        session.commit()
    isolated_headers = {"X-Actor": subject, "X-Workspace-Key": workspace_key}
    assert client.get(
        f"/api/v1/radar/saved-views/{view_id}", headers=isolated_headers
    ).status_code == 404
    assert client.delete(
        f"/api/v1/radar/saved-views/{view_id}", headers=isolated_headers
    ).status_code == 404
