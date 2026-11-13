"""Idempotent reference signing for synthetic journeys. Uses only disposable/local keys when configured."""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import Workspace
from threatsight_api.persistence.readiness_models import ReadinessAction
from threatsight_api.persistence.signing_models import EvidenceSignature, EvidenceSigningKey
from threatsight_api.readiness.actions import download_manifest
from threatsight_api.signing import DEFAULT_DEPLOYMENT_ID
from threatsight_api.signing.provider import FileEd25519Provider
from threatsight_api.signing.service import (
    activate_key,
    claim_pending_request,
    ensure_policy,
    process_request,
    register_public_key,
    request_signature,
)


def ensure_closed_for_reference_signature(db: Session, workspace: Workspace, action: ReadinessAction, actor: str) -> None:
    """If a reopened reference action has no signature, return it to closed so it can be signed."""
    from threatsight_api.persistence.signing_models import EvidenceSignature
    from threatsight_api.readiness.actions import close, transition
    from threatsight_api.persistence.readiness_models import ReadinessClosureRequirement

    existing = db.scalar(
        select(EvidenceSignature).where(
            EvidenceSignature.action_id == action.id,
            EvidenceSignature.workspace_id == workspace.id,
        )
    )
    if existing is not None or action.status != "reopened":
        return
    requirements = list(
        db.scalars(
            select(ReadinessClosureRequirement).where(
                ReadinessClosureRequirement.action_id == action.id,
                ReadinessClosureRequirement.workspace_id == workspace.id,
            )
        )
    )
    if not requirements or any(item.mandatory and item.status != "satisfied" for item in requirements):
        return
    transition(db, workspace.tenant_id, workspace.id, action.id, "awaiting_evidence", actor, "workspace-admin")
    transition(db, workspace.tenant_id, workspace.id, action.id, "ready_for_review", actor, "workspace-admin")
    close(
        db,
        workspace.tenant_id,
        workspace.id,
        action.id,
        "resolved_by_evidence",
        "Reference re-closure for deployment signature demonstration. Not compliance certification.",
        actor,
        "workspace-admin",
    )


def ensure_reference_signature(db: Session, workspace: Workspace, action: ReadinessAction, actor: str) -> None:
    """Sign a closed reference action when a local key file is available; otherwise leave a pending request."""
    ensure_policy(db, DEFAULT_DEPLOYMENT_ID)
    existing = db.scalar(
        select(EvidenceSignature).where(
            EvidenceSignature.action_id == action.id,
            EvidenceSignature.workspace_id == workspace.id,
        )
    )
    if existing is not None:
        return
    # Ensure a finalized manifest exists for the closed action.
    download_manifest(db, workspace.tenant_id, workspace.id, action.id, actor)
    db.flush()
    idem = f"ref-sign-{action.id}"
    try:
        request_signature(
            db,
            workspace.tenant_id,
            workspace.id,
            action.id,
            actor,
            "workspace-admin",
            idempotency_key=idem,
        )
    except Exception:
        # Not eligible yet (e.g. no active key) — leave unsigned.
        return
    # Prefer the dedicated evidence-signer. Inline signing is only for disposable
    # test processes that intentionally mount a local key file.
    key_path = Path(os.environ.get("THREATSIGHT_EVIDENCE_SIGNING_KEY_FILE", ""))
    key_id = os.environ.get("THREATSIGHT_EVIDENCE_SIGNING_KEY_ID", "local-ed25519-1")
    if not key_path.is_file():
        return
    provider = FileEd25519Provider(key_path=key_path, key_id=key_id)
    ok, _ = provider.ready()
    if not ok:
        return
    material = provider.public_material()
    register_public_key(
        db,
        key_id=material.key_id,
        deployment_id=DEFAULT_DEPLOYMENT_ID,
        public_key_pem=material.public_key_pem,
        fingerprint=material.fingerprint,
        provider_type=material.provider_type,
        maturity="fixture_tested",
        actor=actor,
        tenant_id=workspace.tenant_id,
        workspace_id=workspace.id,
    )
    key = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == material.key_id))
    if key is not None and key.status != "active":
        activate_key(
            db,
            key_id=material.key_id,
            deployment_id=DEFAULT_DEPLOYMENT_ID,
            actor=actor,
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
        )
    claimed = claim_pending_request(db, worker_id="reference-loader", deployment_id=DEFAULT_DEPLOYMENT_ID)
    if claimed is None:
        return
    process_request(db, claimed, provider, deployment_id=DEFAULT_DEPLOYMENT_ID)


def install(connection) -> None:
    """Optional post-migration hook; signing completes when a key is mounted."""
    session = Session(bind=connection)
    try:
        ensure_policy(session, DEFAULT_DEPLOYMENT_ID)
        session.commit()
    finally:
        session.close()
