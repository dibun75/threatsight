"""Workspace-scoped verifiable-evidence APIs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from threatsight_api.api.deps import Actor, DbSession, WorkspaceScope
from threatsight_api.persistence.signing_models import EvidenceSigningKey, EvidenceSigningRequest
from threatsight_api.signing import DEFAULT_DEPLOYMENT_ID
from threatsight_api.signing import service as signing_service

router = APIRouter(prefix="/evidence/signing", tags=["evidence-signing"])

ADMIN = frozenset({"workspace-admin", "platform-admin", "admin"})
OPS = ADMIN | frozenset({"operator", "reviewer"})
PLATFORM = frozenset({"platform-admin", "admin"})


class SignRequestBody(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=200)


class KillSwitchBody(BaseModel):
    enabled: bool


class KeyStatusBody(BaseModel):
    status: str = Field(pattern="^(active|retired|revoked)$")
    reason: str = Field(default="", max_length=500)


def _require(role: str, allowed: frozenset[str]) -> None:
    if role not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient role")


@router.get("/actions/{action_id}/eligibility")
def eligibility(action_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    return signing_service.eligibility(db, workspace.tenant_id, workspace.id, action_id)


@router.post("/actions/{action_id}/request")
def request_signature(action_id: uuid.UUID, body: SignRequestBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    _require(workspace.role, ADMIN)
    result = signing_service.request_signature(
        db,
        workspace.tenant_id,
        workspace.id,
        action_id,
        actor,
        workspace.role,
        idempotency_key=body.idempotency_key,
    )
    db.commit()
    return result


@router.get("/requests/{request_id}")
def request_status(request_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = db.scalar(
        select(EvidenceSigningRequest).where(
            EvidenceSigningRequest.id == request_id,
            EvidenceSigningRequest.tenant_id == workspace.tenant_id,
            EvidenceSigningRequest.workspace_id == workspace.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    return signing_service._request_out(row)


@router.get("/actions/{action_id}/signature")
def action_signature(action_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession) -> dict:
    row = signing_service.signature_for_action(db, workspace.tenant_id, workspace.id, action_id)
    if row is None:
        return {"status": "unsigned", "label": "Unsigned", "does_not_mean": "An integrity digest is not a signature."}
    return row


@router.get("/signatures/{signature_id}")
def signature_detail(signature_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    return signing_service.verify_signature(db, workspace.tenant_id, workspace.id, signature_id, actor)


@router.post("/signatures/{signature_id}/verify")
def verify(signature_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    result = signing_service.verify_signature(db, workspace.tenant_id, workspace.id, signature_id, actor)
    db.commit()
    return result


@router.post("/signatures/{signature_id}/bundle")
def download_bundle(signature_id: uuid.UUID, workspace: WorkspaceScope, db: DbSession, actor: Actor, response: Response) -> dict:
    body = signing_service.build_bundle(db, workspace.tenant_id, workspace.id, signature_id, actor)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Disposition"] = f'attachment; filename="{body["filename"]}"'
    return body


@router.get("/keys")
def list_keys(workspace: WorkspaceScope, db: DbSession) -> dict:
    return signing_service.list_public_keys(db)


@router.get("/health")
def signing_health(workspace: WorkspaceScope, db: DbSession) -> dict:
    _require(workspace.role, OPS)
    return signing_service.operational_health(db)


@router.post("/kill-switch")
def kill_switch(body: KillSwitchBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    _require(workspace.role, PLATFORM)
    policy = signing_service.set_kill_switch(
        db,
        enabled=body.enabled,
        actor=actor,
        tenant_id=workspace.tenant_id,
        workspace_id=workspace.id,
    )
    db.commit()
    return {"kill_switch": policy.kill_switch, "deployment_id": policy.deployment_id}


@router.post("/keys/{key_id}/status")
def key_status(key_id: str, body: KeyStatusBody, workspace: WorkspaceScope, db: DbSession, actor: Actor) -> dict:
    _require(workspace.role, PLATFORM)
    if len(key_id) > 64:
        raise HTTPException(status_code=422, detail="Invalid key id")
    if body.status == "active":
        row = signing_service.activate_key(
            db,
            key_id=key_id,
            deployment_id=DEFAULT_DEPLOYMENT_ID,
            actor=actor,
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
        )
    elif body.status == "revoked":
        row = signing_service.revoke_key(
            db,
            key_id=key_id,
            actor=actor,
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
            reason=body.reason or "revoked",
        )
    else:
        row = db.scalar(select(EvidenceSigningKey).where(EvidenceSigningKey.key_id == key_id))
        if row is None:
            raise HTTPException(status_code=404, detail="Not found")
        row.status = "retired"
        row.is_default = False
        row.retired_at = datetime.now(UTC)
        db.flush()
    db.commit()
    return {"key_id": row.key_id, "status": row.status, "fingerprint": row.public_key_fingerprint}
