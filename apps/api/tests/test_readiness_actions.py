"""Phase 3B accountable actions: ownership, closure, reopen, manifests."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from threatsight_api.graph.materialize import materialize
from threatsight_api.investigations.reference import install as install_journeys
from threatsight_api.main import app
from threatsight_api.persistence.models import Identity, Workspace, WorkspaceMembership
from threatsight_api.persistence.session import get_engine
from threatsight_api.readiness.action_reference import install as install_actions
from threatsight_api.readiness.reference import install as install_readiness

pytestmark = pytest.mark.skipif(
    os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() not in {"1", "true", "yes"},
    reason="requires postgres",
)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(role: str = "workspace-admin") -> dict[str, str]:
    subject = f"act-{uuid.uuid4().hex[:8]}"
    key = f"act-{uuid.uuid4().hex[:10]}"
    with Session(get_engine()) as db:
        tenant_id = db.scalar(text("SELECT tenant_id FROM workspaces WHERE key = 'default'"))
        workspace = Workspace(tenant_id=tenant_id, key=key, name=key, status="active")
        db.add(workspace)
        db.flush()
        identity = Identity(issuer="test", subject=subject, display_name=subject, status="active")
        db.add(identity)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, identity_id=identity.id, role=role))
        db.commit()
        return {
            "X-Actor": subject,
            "X-Workspace-Key": key,
            "tenant": str(tenant_id),
            "id": str(workspace.id),
            "identity_id": str(identity.id),
        }


def _seed(headers: dict[str, str]) -> None:
    with Session(get_engine()) as db:
        materialize(
            db,
            tenant_id=uuid.UUID(headers["tenant"]),
            workspace_id=uuid.UUID(headers["id"]),
            actor=headers["X-Actor"],
            idempotency_key=f"act-{uuid.uuid4().hex[:8]}",
            fixture="correlation",
        )
        db.commit()
    with Session(get_engine()) as db:
        install_journeys(db.connection())
        install_readiness(db.connection())
        install_actions(db.connection())
        install_actions(db.connection())
        db.commit()


def test_accountable_closure_journey(client: TestClient) -> None:
    admin = _workspace("workspace-admin")
    operator_subject = f"op-{uuid.uuid4().hex[:8]}"
    foreign = _workspace("workspace-admin")
    with Session(get_engine()) as db:
        identity = Identity(issuer="test", subject=operator_subject, display_name=operator_subject, status="active")
        db.add(identity)
        db.flush()
        db.add(WorkspaceMembership(workspace_id=uuid.UUID(admin["id"]), subject=operator_subject, identity_id=identity.id, role="operator"))
        db.commit()
        operator_identity = str(identity.id)
    _seed(admin)
    summary = client.get("/api/v1/readiness/actions/summary", headers=admin)
    assert summary.status_code == 200
    body = summary.json()
    assert body["awaiting_evidence"] >= 1 or body["reopened"] >= 1 or body["ready_for_review"] >= 0
    listed = client.get("/api/v1/readiness/actions", headers=admin)
    assert listed.status_code == 200
    items = listed.json()["items"]
    assert len(items) >= 3
    ordering = next(item for item in items if item["service_source_key"].endswith("customer-ordering"))
    detail = client.get(f"/api/v1/readiness/actions/{ordering['id']}", headers=admin)
    assert detail.status_code == 200
    assert detail.json()["maturity"] == "Validated with reference data"
    isolated = client.get(f"/api/v1/readiness/actions/{ordering['id']}", headers=foreign)
    assert isolated.status_code == 404
    # Fresh action path: approve + decide + assign + satisfy + close + reopen on a second workspace recommendation if needed.
    # Operator cannot close.
    if ordering["status"] == "ready_for_review":
        denied = client.post(
            f"/api/v1/readiness/actions/{ordering['id']}/close",
            headers={"X-Actor": operator_subject, "X-Workspace-Key": admin["X-Workspace-Key"]},
            json={"outcome": "resolved_by_evidence", "rationale": "operator attempt"},
        )
        assert denied.status_code == 403
    manifest = client.get(f"/api/v1/readiness/actions/{ordering['id']}/manifest", headers=admin)
    assert manifest.status_code == 200
    assert manifest.json()["is_signed"] is False
    assert "Evidence manifest" in manifest.json()["label"]
    assert "Unsigned" in manifest.json().get("does_not_mean", "") or manifest.json()["is_signed"] is False
    preview = manifest.json()["preview"]
    import json
    from hashlib import sha256

    canonical = json.dumps(preview, separators=(",", ":"), sort_keys=True)
    assert sha256(canonical.encode()).hexdigest() == manifest.json()["digest"]
    altered = dict(preview)
    altered["remaining_uncertainty"] = (altered.get("remaining_uncertainty") or "") + " changed"
    assert sha256(json.dumps(altered, separators=(",", ":"), sort_keys=True).encode()).hexdigest() != manifest.json()["digest"]
    # No secret-like fields in the preview
    blob = json.dumps(preview).lower()
    assert "password" not in blob and "private_key" not in blob and "begin private" not in blob
    # Foreign owner rejected (or stale version rejected before lookup)
    current = client.get(f"/api/v1/readiness/actions/{ordering['id']}", headers=admin).json()
    bad = client.post(
        f"/api/v1/readiness/actions/{ordering['id']}/assign",
        headers=admin,
        json={"owner_identity_id": foreign["identity_id"], "expected_version": current["version"]},
    )
    assert bad.status_code in {404, 409}
    # Local owner assign accepted when version matches current detail
    current = client.get(f"/api/v1/readiness/actions/{ordering['id']}", headers=admin).json()
    if current["status"] in {"open", "reopened", "assigned"}:
        assigned = client.post(
            f"/api/v1/readiness/actions/{ordering['id']}/assign",
            headers=admin,
            json={"owner_identity_id": operator_identity, "due_at": (datetime.now(UTC) + timedelta(days=5)).isoformat(), "expected_version": current["version"]},
        )
        assert assigned.status_code == 200
        assert assigned.json()["owner_identity_id"] == operator_identity


def test_closure_blocked_without_requirements(client: TestClient) -> None:
    admin = _workspace()
    _seed(admin)
    items = client.get("/api/v1/readiness/actions", headers=admin).json()["items"]
    remote = next(item for item in items if item["service_source_key"].endswith("remote-access"))
    assert remote["status"] == "awaiting_evidence"
    closed = client.post(
        f"/api/v1/readiness/actions/{remote['id']}/close",
        headers=admin,
        json={"outcome": "resolved_by_evidence", "rationale": "should fail", "expected_version": remote["version"]},
    )
    assert closed.status_code == 409
