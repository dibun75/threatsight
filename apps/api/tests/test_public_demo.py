from __future__ import annotations

import os
import time
import uuid

import pytest
from pydantic import ValidationError

from threatsight_api.config import Settings, get_settings

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}


def test_expensive_routes_have_a_separate_public_demo_budget() -> None:
    from threatsight_api import authz

    authz._PUBLIC_WINDOW.update(start=time.monotonic(), count=0)
    authz._EXPENSIVE_WINDOW.update(start=time.monotonic(), count=authz.PUBLIC_DEMO_EXPENSIVE_LIMIT)
    try:
        assert authz.public_demo_request_allowed("/api/v1/radar/workspace") is True
        assert authz.public_demo_request_allowed("/api/v1/graph/snapshots/current") is False
        assert authz.public_demo_request_allowed("/api/v1/landscape/summary") is False
    finally:
        authz._PUBLIC_WINDOW.update(start=0.0, count=0)
        authz._EXPENSIVE_WINDOW.update(start=0.0, count=0)


def test_public_demo_requires_an_explicit_flag_and_cannot_be_production() -> None:
    with pytest.raises(ValidationError):
        Settings(auth_mode=" ")
    settings = Settings(auth_mode="public_demo", public_demo=False)
    with pytest.raises(ValueError, match="PUBLIC_DEMO"):
        settings.validate_runtime_security()
    production = Settings(env="production", auth_mode="public_demo", public_demo=True)
    with pytest.raises(ValueError, match="production"):
        production.validate_runtime_security()


@pytest.mark.skipif(not LIVE, reason="requires live postgres")
def test_public_demo_is_read_only_and_cannot_see_another_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREATSIGHT_AUTH_MODE", "public_demo")
    monkeypatch.setenv("THREATSIGHT_PUBLIC_DEMO", "true")
    get_settings.cache_clear()
    from fastapi.testclient import TestClient
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from threatsight_api.main import app
    from threatsight_api.persistence.models import BusinessService, Tenant, Workspace
    from threatsight_api.persistence.session import get_engine

    marker = f"customer-only-{uuid.uuid4().hex[:8]}"
    other_key = f"customer-{uuid.uuid4().hex[:8]}"
    try:
        with TestClient(app) as client:
            with Session(get_engine()) as session:
                demo = session.scalar(select(Workspace).where(Workspace.key == "default"))
                tenant = session.get(Tenant, demo.tenant_id)
                other = Workspace(tenant_id=tenant.id, key=other_key, name="Customer workspace", classification="unspecified")
                session.add(other)
                session.flush()
                session.add(BusinessService(workspace_id=other.id, key=marker, name=marker, criticality="high"))
                session.commit()
                other_id = other.id
            spoofed = {
                "X-Actor": "operator",
                "X-Role": "platform-admin",
                "X-Workspace-Key": other_key,
                "Cf-Access-Authenticated-User-Email": "other@example.com",
            }
            workspace = client.get("/api/v1/radar/workspace", headers=spoofed, params={"workspace": other_key})
            assert workspace.status_code == 200
            body = workspace.json()
            assert body["subject"] == "demo-viewer"
            assert body["role"] == "viewer"
            assert body["key"] == "default"
            resources = client.get("/api/v1/radar/resources", headers={"X-Workspace-Key": other_key})
            assert resources.status_code == 200
            assert marker not in resources.text
            missing = client.get(f"/api/v1/graph/nodes/{other_id}", headers={"X-Workspace-Key": other_key})
            assert missing.status_code == 404
            mutations = [
                ("/api/v1/radar/saved-views", {"name": "x", "filters": {}}),
                ("/api/v1/radar/triage/event/" + str(uuid.uuid4()), {"status": "reviewing", "priority": "low", "rationale": "no"}),
                ("/api/v1/graph/builds", {}),
                ("/api/v1/analysis/runs", {}),
                ("/api/v1/correlation/runs", {}),
                ("/api/v1/connectors/jobs", {}),
                ("/api/v1/connectors/runners", {"name": "x"}),
                ("/api/v1/evidence", {"title": "x", "owner": "x"}),
                ("/api/v1/assurance/runs", {}),
                ("/api/v1/systems", {"name": "x"}),
            ]
            for path, payload in mutations:
                response = client.post(path, json=payload, headers=spoofed)
                assert response.status_code == 403, path
            assert client.get("/api/v1/connectors/secret-references", headers=spoofed).status_code == 403
            assert client.get("/api/v1/ops/config", headers=spoofed).status_code == 403
            assert client.get("/api/v1/ops/execution", headers=spoofed).status_code == 403
            from threatsight_api import authz

            authz._PUBLIC_WINDOW.update(start=time.monotonic(), count=authz.PUBLIC_DEMO_LIMIT)
            limited = client.get("/api/v1/radar/workspace")
            assert limited.status_code == 429
            assert limited.headers.get("retry-after") == "60"
            authz._PUBLIC_WINDOW.update(start=0.0, count=0)
            authz._EXPENSIVE_WINDOW.update(start=0.0, count=0)
            ready = client.get("/ready")
            assert ready.status_code == 200
    finally:
        get_settings.cache_clear()
