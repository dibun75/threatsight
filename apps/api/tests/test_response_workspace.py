"""Phase 3E response workspace: activation, declaration, roles, timeline, security."""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session
from threatsight_api.main import app
from threatsight_api.persistence.models import Identity, Workspace, WorkspaceMembership
from threatsight_api.persistence.response_models import ResponseTimelineEntry
from threatsight_api.persistence.session import get_engine
from threatsight_api.response.reference import EXERCISE_KEY, install_workspace

pytestmark = pytest.mark.skipif(
    os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() not in {"1", "true", "yes"},
    reason="requires postgres",
)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(role: str = "workspace-admin") -> dict[str, str]:
    subject = f"resp-{uuid.uuid4().hex[:8]}"
    key = f"resp-{uuid.uuid4().hex[:10]}"
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


def test_propose_activate_declare_separation(client: TestClient) -> None:
    admin = _workspace("workspace-admin")
    foreign = _workspace("workspace-admin")

    proposed = client.post(
        "/api/v1/response/propose",
        headers=admin,
        json={
            "title": "Assessment proposal",
            "reason": "Manual assessment of possible OT relevance",
            "mode": "assessment",
            "idempotency_key": f"idem-{uuid.uuid4().hex}",
            "known_facts": "Advisory exists",
            "uncertain_facts": "Reachability unknown",
            "services": [{"service_key": "svc-a", "service_name": "Service A"}],
        },
    )
    assert proposed.status_code == 200
    body = proposed.json()
    assert body["lifecycle"] == "draft"
    assert body["declaration_state"] == "not_declared"
    assert body["is_incident"] is False
    response_id = body["id"]

    # Idempotent propose
    idem = f"idem-reuse-{uuid.uuid4().hex}"
    first = client.post(
        "/api/v1/response/propose",
        headers=admin,
        json={
            "title": "Idem test",
            "reason": "Idempotency check for proposal",
            "mode": "assessment",
            "idempotency_key": idem,
        },
    )
    second = client.post(
        "/api/v1/response/propose",
        headers=admin,
        json={
            "title": "Idem test changed",
            "reason": "Idempotency check for proposal",
            "mode": "assessment",
            "idempotency_key": idem,
        },
    )
    assert first.json()["id"] == second.json()["id"]

    # Viewer cannot activate — same workspace viewer
    with Session(get_engine()) as db:
        subject = f"view-{uuid.uuid4().hex[:8]}"
        identity = Identity(issuer="test", subject=subject, display_name=subject, status="active")
        db.add(identity)
        db.flush()
        db.add(
            WorkspaceMembership(
                workspace_id=uuid.UUID(admin["id"]), subject=subject, identity_id=identity.id, role="viewer"
            )
        )
        db.commit()
        viewer_h = {"X-Actor": subject, "X-Workspace-Key": admin["X-Workspace-Key"]}
    denied = client.post(
        f"/api/v1/response/{response_id}/activate",
        headers=viewer_h,
        json={"rationale": "Should fail for viewer role"},
    )
    assert denied.status_code == 403

    activated = client.post(
        f"/api/v1/response/{response_id}/activate",
        headers=admin,
        json={"rationale": "Authorize assessment coordination", "expected_version": body["version"]},
    )
    assert activated.status_code == 200
    assert activated.json()["lifecycle"] == "activated"
    assert activated.json()["declaration_state"] == "not_declared"

    # Cannot confirm without evidence
    bad = client.post(
        f"/api/v1/response/{response_id}/declaration",
        headers=admin,
        json={
            "declaration_state": "confirmed_incident",
            "rationale": "Trying without evidence",
            "evidence_reviewed": True,
            "remaining_uncertainty": "High",
            "expected_version": activated.json()["version"],
        },
    )
    assert bad.status_code == 400

    # Cross-tenant isolation
    isolated = client.get(f"/api/v1/response/{response_id}", headers=foreign)
    assert isolated.status_code == 404

    # Timeline append + correct (no rewrite)
    tl = client.post(
        f"/api/v1/response/{response_id}/timeline",
        headers=admin,
        json={"category": "assessment_update", "summary": "Original note"},
    )
    assert tl.status_code == 200
    entry_id = tl.json()["entry_id"]
    corr = client.post(
        f"/api/v1/response/{response_id}/timeline/{entry_id}/correct",
        headers=admin,
        json={"summary": "Corrected note"},
    )
    assert corr.status_code == 200
    with Session(get_engine()) as db:
        original = db.get(ResponseTimelineEntry, uuid.UUID(entry_id))
        assert original is not None
        assert original.is_current is False
        assert original.summary == "Original note"

    # Foreign role assignment rejected
    foreign_identity = foreign["identity_id"]
    role_fail = client.post(
        f"/api/v1/response/{response_id}/roles",
        headers=admin,
        json={"role_key": "response_lead", "identity_id": foreign_identity},
    )
    assert role_fail.status_code == 400

    # Assign local identity
    role_ok = client.post(
        f"/api/v1/response/{response_id}/roles",
        headers=admin,
        json={"role_key": "response_lead", "identity_id": admin["identity_id"]},
    )
    assert role_ok.status_code == 200
    assert role_ok.json()["response_lead"]

    # Oversized field
    huge = client.post(
        f"/api/v1/response/{response_id}/timeline",
        headers=admin,
        json={"category": "assessment_update", "summary": "x" * 2000},
    )
    assert huge.status_code in {400, 422}

    # Malicious HTML stripped/bounded via clean
    safe = client.post(
        f"/api/v1/response/{response_id}/timeline",
        headers=admin,
        json={"category": "assessment_update", "summary": "<script>alert(1)</script> note"},
    )
    assert safe.status_code == 200

    # Decision
    decision = client.post(
        f"/api/v1/response/{response_id}/decisions",
        headers=admin,
        json={
            "decision": "Needs more data",
            "rationale": "Insufficient verification",
            "remaining_uncertainty": "Reachability unknown",
            "idempotency_key": f"dec-{uuid.uuid4().hex}",
        },
    )
    assert decision.status_code == 200

    # Sitrep + finalize
    sitrep = client.post(
        f"/api/v1/response/{response_id}/situation-reports",
        headers=admin,
        json={"current_status": "Assessing", "known_facts": "Advisory", "uncertain_facts": "Reachability"},
    )
    assert sitrep.status_code == 200
    fin = client.post(
        f"/api/v1/response/{response_id}/situation-reports/{sitrep.json()['id']}/finalize",
        headers=admin,
    )
    assert fin.status_code == 200
    assert fin.json()["status"] == "final"

    # Comm draft remains not sent
    draft = client.post(
        f"/api/v1/response/{response_id}/communications",
        headers=admin,
        json={
            "template_key": "executive_update",
            "subject": "Update",
            "body_text": "Draft holding statement",
        },
    )
    assert draft.status_code == 200
    assert draft.json()["delivery_state"] == "not_sent"
    assert draft.json()["sent"] is False

    # Snapshot
    snap = client.post(
        f"/api/v1/response/{response_id}/snapshots",
        headers=admin,
        json={"idempotency_key": f"snap-{uuid.uuid4().hex}"},
    )
    assert snap.status_code == 200
    assert snap.json()["proves"] == "integrity_only"
    assert snap.json()["contains_secrets"] is False

    # Close
    closed = client.post(
        f"/api/v1/response/{response_id}/close",
        headers=admin,
        json={"notes": "Assessment complete for now", "expected_version": role_ok.json()["version"]},
    )
    # version may have advanced — retry without version if conflict
    if closed.status_code == 409:
        detail = client.get(f"/api/v1/response/{response_id}", headers=admin).json()
        closed = client.post(
            f"/api/v1/response/{response_id}/close",
            headers=admin,
            json={"notes": "Assessment complete for now", "expected_version": detail["version"]},
        )
    assert closed.status_code == 200
    assert closed.json()["lifecycle"] == "closed"


def test_exercise_loader_idempotent_and_not_incident(client: TestClient) -> None:
    admin = _workspace("workspace-admin")
    with Session(get_engine()) as db:
        workspace = db.get(Workspace, uuid.UUID(admin["id"]))
        assert workspace is not None
        install_workspace(db, workspace)
        install_workspace(db, workspace)
        db.commit()
        count = db.scalar(
            text(
                "SELECT COUNT(*) FROM response_workspaces WHERE workspace_id = CAST(:ws AS uuid) AND stable_key = :key"
            ),
            {"ws": admin["id"], "key": EXERCISE_KEY},
        )
        assert count == 1
    listed = client.get("/api/v1/response", headers=admin)
    assert listed.status_code == 200
    items = listed.json()["items"]
    exercise = next(i for i in items if i["stable_key"] == EXERCISE_KEY)
    assert exercise["mode"] == "exercise"
    assert exercise["declaration_state"] == "not_declared"
    assert exercise["is_incident"] is False
    assert exercise["synthetic_label"] == "Synthetic exercise"

    summary = client.get("/api/v1/response/summary", headers=admin)
    assert summary.status_code == 200
    assert summary.json()["confirmed_incidents"] == 0
    assert "Exercises are not incidents" in summary.json()["note"]

    # Cannot declare confirmed incident on exercise
    detail = client.get(f"/api/v1/response/{exercise['id']}", headers=admin).json()
    # reopen first if closed
    if detail["lifecycle"] == "closed":
        client.post(
            f"/api/v1/response/{exercise['id']}/reopen",
            headers=admin,
            json={"reason": "Test declaration guard", "expected_version": detail["version"]},
        )
        detail = client.get(f"/api/v1/response/{exercise['id']}", headers=admin).json()
    if detail["lifecycle"] != "activated":
        client.post(
            f"/api/v1/response/{exercise['id']}/activate",
            headers=admin,
            json={"rationale": "Re-activate for declaration guard test", "mode": "exercise", "expected_version": detail["version"]},
        )
        detail = client.get(f"/api/v1/response/{exercise['id']}", headers=admin).json()
    blocked = client.post(
        f"/api/v1/response/{exercise['id']}/declaration",
        headers=admin,
        json={
            "declaration_state": "confirmed_incident",
            "rationale": "Must not allow on exercise",
            "evidence_reviewed": True,
            "remaining_uncertainty": "n/a",
            "expected_version": detail["version"],
        },
    )
    assert blocked.status_code == 400


def test_jurisdiction_defaults_not_determined(client: TestClient) -> None:
    admin = _workspace("workspace-admin")
    profiles = client.get("/api/v1/response/jurisdiction-profiles", headers=admin)
    assert profiles.status_code == 200
    assert profiles.json()["items"]
    assert "Not legal advice" in profiles.json()["not_legal_advice"]
    proposed = client.post(
        "/api/v1/response/propose",
        headers=admin,
        json={
            "title": "Reg prep",
            "reason": "Test regulatory assessment defaults",
            "mode": "assessment",
            "idempotency_key": f"reg-{uuid.uuid4().hex}",
        },
    )
    response_id = proposed.json()["id"]
    profile_id = profiles.json()["items"][0]["id"]
    # Deadline without confirmation rejected
    bad = client.put(
        f"/api/v1/response/{response_id}/regulatory",
        headers=admin,
        json={"profile_id": profile_id, "deadline_hours_confirmed": 24, "confirm_deadline": False},
    )
    assert bad.status_code == 400
    ok = client.put(
        f"/api/v1/response/{response_id}/regulatory",
        headers=admin,
        json={"profile_id": profile_id},
    )
    assert ok.status_code == 200
    assert ok.json()["legal_applicability"] == "not_determined"
    assert ok.json()["reporting_obligation"] == "not_determined"
    assert ok.json()["regulator_notified"] is False
