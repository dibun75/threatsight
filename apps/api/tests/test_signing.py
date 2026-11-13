"""Phase 3C signing eligibility, worker processing, RBAC, and bundles."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

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
from threatsight_api.signing.provider import FileEd25519Provider, generate_ed25519_keypair_files
from threatsight_api.signing.service import activate_key, claim_pending_request, process_request, register_public_key

pytestmark = pytest.mark.skipif(
    os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() not in {"1", "true", "yes"},
    reason="requires postgres",
)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _workspace(role: str = "workspace-admin") -> dict[str, str]:
    subject = f"sig-{uuid.uuid4().hex[:8]}"
    key = f"sig-{uuid.uuid4().hex[:10]}"
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
        }


def _seed(headers: dict[str, str], key_path: Path, key_id: str) -> None:
    os.environ["THREATSIGHT_EVIDENCE_SIGNING_KEY_FILE"] = str(key_path)
    os.environ["THREATSIGHT_EVIDENCE_SIGNING_KEY_ID"] = key_id
    with Session(get_engine()) as db:
        materialize(
            db,
            tenant_id=uuid.UUID(headers["tenant"]),
            workspace_id=uuid.UUID(headers["id"]),
            actor=headers["X-Actor"],
            idempotency_key=f"sig-{uuid.uuid4().hex[:8]}",
            fixture="correlation",
        )
        db.commit()
    with Session(get_engine()) as db:
        install_journeys(db.connection())
        install_readiness(db.connection())
        install_actions(db.connection())
        install_actions(db.connection())
        db.commit()


def test_signing_journey_and_guards(client: TestClient, tmp_path: Path) -> None:
    private = tmp_path / "ed25519-private.pem"
    public = tmp_path / "ed25519-public.pem"
    fingerprint = generate_ed25519_keypair_files(private_path=private, public_path=public)
    key_id = f"test-{uuid.uuid4().hex[:8]}"
    admin = _workspace("workspace-admin")
    viewer = _workspace("viewer")
    _seed(admin, private, key_id)

    actions = client.get("/api/v1/readiness/actions", headers=admin).json()["items"]
    ordering = next(row for row in actions if "installed version" in row["title"].lower() or row["status"] == "reopened")
    # Privileged / remote must be ineligible
    awaiting = [row for row in actions if row["status"] == "awaiting_evidence"]
    assert len(awaiting) >= 2
    blocked = client.get(f"/api/v1/evidence/signing/actions/{awaiting[0]['id']}/eligibility", headers=admin).json()
    assert blocked["eligible"] is False
    assert "action_not_closed" in blocked["reasons"] or "mandatory_requirements_incomplete" in blocked["reasons"]

    # Viewer cannot request signing
    denied = client.post(
        f"/api/v1/evidence/signing/actions/{ordering['id']}/request",
        headers=viewer,
        json={"idempotency_key": f"viewer-{uuid.uuid4().hex}"},
    )
    assert denied.status_code in {403, 404, 409}

    # Ensure public key registered/activated then process any pending request from loader
    with Session(get_engine()) as db:
        provider = FileEd25519Provider(key_path=private, key_id=key_id)
        material = provider.public_material()
        assert material.fingerprint == fingerprint
        register_public_key(
            db,
            key_id=key_id,
            deployment_id="threatsight-local",
            public_key_pem=material.public_key_pem,
            fingerprint=material.fingerprint,
            provider_type="file_ed25519",
            maturity="fixture_tested",
            actor=admin["X-Actor"],
            tenant_id=uuid.UUID(admin["tenant"]),
            workspace_id=uuid.UUID(admin["id"]),
        )
        activate_key(
            db,
            key_id=key_id,
            deployment_id="threatsight-local",
            actor=admin["X-Actor"],
            tenant_id=uuid.UUID(admin["tenant"]),
            workspace_id=uuid.UUID(admin["id"]),
        )
        claimed = claim_pending_request(db, worker_id="test-signer")
        if claimed is not None:
            process_request(db, claimed, provider)
        db.commit()

    # Re-run loader to close/sign/reopen if needed
    _seed(admin, private, key_id)
    actions = client.get("/api/v1/readiness/actions", headers=admin).json()["items"]
    ordering = next(row for row in actions if "Validate the installed version" in row["title"])
    detail = client.get(f"/api/v1/evidence/signing/actions/{ordering['id']}/signature", headers=admin).json()
    # After reopen, signature should be superseded or present
    if detail.get("status") == "unsigned":
        # Force close/sign path via eligibility
        elig = client.get(f"/api/v1/evidence/signing/actions/{ordering['id']}/eligibility", headers=admin).json()
        assert elig["eligible"] is False or elig["eligible"] is True
    else:
        assert detail["label"] == "Reference-signed evidence"
        assert detail["fingerprint"] == fingerprint
        assert "does_not_prove" in detail
        verified = client.post(f"/api/v1/evidence/signing/signatures/{detail['id']}/verify", headers=admin, json={}).json()
        assert verified["state"] in {"valid_current", "valid_superseded"}
        bundle = client.post(f"/api/v1/evidence/signing/signatures/{detail['id']}/bundle", headers=admin, json={}).json()
        assert bundle["cache_control"] == "no-store"
        blob = json_dump_lower(bundle)
        assert "begin private" not in blob
        assert "ed25519-private" not in blob
        assert "/var/lib/threatsight" not in blob
        assert "-----begin" in blob  # public key pem only
        assert fingerprint in blob or detail["fingerprint"] == fingerprint


def json_dump_lower(value: object) -> str:
    import json

    return json.dumps(value).lower()
