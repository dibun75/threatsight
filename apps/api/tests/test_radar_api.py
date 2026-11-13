from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from threatsight_api.main import app
from threatsight_api.persistence.models import Workspace
from threatsight_api.persistence.session import get_engine

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires live postgres")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_default_workspace_profile_and_source_health(client: TestClient) -> None:
    headers = {"X-Actor": "operator"}
    context = client.get("/api/v1/radar/workspace", headers=headers)
    assert context.status_code == 200, context.text
    assert context.json()["key"] == "default"
    assert context.json()["isolation"] == "membership_enforced"

    profile = client.get("/api/v1/radar/profile", headers=headers)
    assert profile.status_code == 200, profile.text
    assert "NO" in profile.json()["countries"]

    sources = client.get("/api/v1/radar/sources", headers=headers)
    assert sources.status_code == 200, sources.text
    keys = {item["key"] for item in sources.json()}
    assert keys >= {
        "cisa-kev",
        "nsm-rss",
        "first-epss",
        "cert-se-atom",
        "ncsc-fi-rss",
        "enisa-euvd",
        "cert-eu-rss",
        "samsik-manual",
        "cert-is-manual",
        "msrc-csaf",
        "juniper-psirt",
        "cisco-openvuln",
    }


def test_cross_workspace_reads_and_writes_are_denied(client: TestClient) -> None:
    key = f"isolated-{uuid.uuid4().hex[:8]}"
    with Session(get_engine()) as session:
        session.add(Workspace(key=key, name="Isolated test workspace", status="active"))
        session.commit()

    headers = {"X-Actor": "operator", "X-Workspace-Key": key}
    read = client.get("/api/v1/radar/events", headers=headers)
    assert read.status_code == 403
    write = client.put(
        "/api/v1/radar/profile",
        headers=headers,
        json={"countries": ["SE"], "minimum_relevance": 0},
    )
    assert write.status_code == 403
