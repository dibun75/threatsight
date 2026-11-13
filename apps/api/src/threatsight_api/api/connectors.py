from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatsight_api.api.deps import DbSession, WorkspaceScope
from threatsight_api.config import get_settings
from threatsight_api.connectors.execution import (
    add_audit,
    authenticate_runner,
    claim_job,
    complete_job,
    contains_secret_material,
    fail_job,
    issue_runner_token,
    payload_too_large,
    redact,
)
from threatsight_api.connectors.microsoft.registry import accepted_instance, accepted_job_input
from threatsight_api.connectors.sdk import CollectionEnvelope, ConnectorHealth
from threatsight_api.persistence.models import (
    AuditEvent,
    ConnectorInstance,
    ConnectorJob,
    ConnectorJobAudit,
    RunnerCredential,
    RunnerRegistration,
    SecretReference,
)
from threatsight_api.persistence.session import get_db

router = APIRouter(prefix="/connectors", tags=["connectors"])
runner_router = APIRouter(prefix="/runner/v1", tags=["runner"])
ADMIN_ROLES = frozenset({"workspace-admin", "platform-admin"})
WRITE_ROLES = frozenset({"operator", "workspace-admin", "platform-admin"})


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SecretReferenceIn(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    provider: Literal["customer_runner", "vault", "azure_key_vault", "aws_secrets_manager", "gcp_secret_manager"]
    locator: str = Field(min_length=1, max_length=1000)
    version_hint: str | None = Field(default=None, max_length=200)


class RunnerIn(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    capabilities: list[str] = Field(default_factory=list, max_length=50)


class ConnectorIn(StrictModel):
    connector_key: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    name: str = Field(min_length=1, max_length=120)
    runner_id: uuid.UUID | None = None
    secret_reference_id: uuid.UUID | None = None
    mode: Literal["fixture", "live"] = "fixture"
    maturity: Literal["unsupported", "experimental", "fixture_tested", "live_verified"] = "unsupported"
    configuration: dict = Field(default_factory=dict)


class JobIn(StrictModel):
    connector_instance_id: uuid.UUID
    job_type: Literal["inventory", "configuration_evidence", "health"]
    idempotency_key: str = Field(min_length=1, max_length=200)
    input: dict = Field(default_factory=dict)
    priority: int = Field(default=100, ge=0, le=1000)
    max_attempts: int = Field(default=5, ge=1, le=10)


class ProgressIn(StrictModel):
    progress: dict


class FailureIn(StrictModel):
    code: str = Field(min_length=1, max_length=64)
    detail: str = Field(min_length=1, max_length=500)
    retryable: bool = True


class HealthIn(StrictModel):
    connector_instance_id: uuid.UUID
    health: ConnectorHealth


def _require_bounded(value: dict, label: str) -> None:
    if payload_too_large(value):
        raise HTTPException(status_code=422, detail=f"{label} exceeds 64 KiB")
    if contains_secret_material(value):
        raise HTTPException(status_code=422, detail=f"{label} cannot contain secret material")


def _require_lease(item: ConnectorJob, runner: RunnerRegistration) -> None:
    if item.status not in {"leased", "running"} or item.lease_owner != f"runner:{runner.id}":
        raise HTTPException(status_code=409, detail="Job lease is not held by this runner")
    if item.lease_expires_at is not None and item.lease_expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=409, detail="Job lease has expired")


def _require(scope: WorkspaceScope, roles: frozenset[str]) -> None:
    if scope.role not in roles:
        raise HTTPException(status_code=403, detail="Workspace role is not permitted")


def _secret_out(item: SecretReference) -> dict:
    return {
        "id": str(item.id), "name": item.name, "provider": item.provider,
        "locator": "[REDACTED]", "version_hint": item.version_hint, "status": item.status,
    }


def _runner_out(item: RunnerRegistration) -> dict:
    return {
        "id": str(item.id), "name": item.name, "status": item.status,
        "capabilities": item.capabilities, "last_seen_at": item.last_seen_at,
        "revoked_at": item.revoked_at,
    }


def _connector_out(item: ConnectorInstance, scope: WorkspaceScope) -> dict:
    payload = {
        "id": str(item.id), "connector_key": item.connector_key, "sdk_version": item.sdk_version,
        "name": item.name, "mode": item.mode, "maturity": item.maturity, "status": item.status,
        "health_state": item.health_state, "health_detail": item.health_detail,
        "last_health_at": item.last_health_at,
    }
    if scope.role != "viewer":
        payload["runner_id"] = str(item.runner_id) if item.runner_id else None
        payload["secret_reference_id"] = str(item.secret_reference_id) if item.secret_reference_id else None
        payload["configuration"] = redact(item.configuration)
    return payload


def _job_out(item: ConnectorJob, include_input: bool = True, hide_runner: bool = False) -> dict:
    output = {
        "id": str(item.id), "connector_instance_id": str(item.connector_instance_id),
        "runner_id": str(item.runner_id) if item.runner_id else None, "job_type": item.job_type,
        "status": item.status, "priority": item.priority, "idempotency_key": item.idempotency_key,
        "progress": redact(item.progress), "attempt_count": item.attempt_count,
        "max_attempts": item.max_attempts, "available_at": item.available_at,
        "lease_expires_at": item.lease_expires_at, "cancel_requested_at": item.cancel_requested_at,
        "last_error_code": item.last_error_code, "last_error_detail": item.last_error_detail,
    }
    if include_input:
        output["input"] = redact(item.input)
    if hide_runner:
        output.pop("runner_id", None)
    return output


@router.get("/secret-references")
def list_secret_references(db: DbSession, scope: WorkspaceScope) -> list[dict]:
    if scope.role == "viewer":
        raise HTTPException(status_code=403, detail="Workspace access denied")
    return [_secret_out(item) for item in db.scalars(select(SecretReference).where(
        SecretReference.tenant_id == scope.tenant_id, SecretReference.workspace_id == scope.id
    ).order_by(SecretReference.name))]


@router.post("/secret-references", status_code=201)
def create_secret_reference(body: SecretReferenceIn, db: DbSession, scope: WorkspaceScope) -> dict:
    _require(scope, ADMIN_ROLES)
    item = SecretReference(tenant_id=scope.tenant_id, workspace_id=scope.id, **body.model_dump())
    db.add(item)
    try:
        db.flush()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Secret-reference name already exists") from None
    return _secret_out(item)


@router.get("/runners")
def list_runners(db: DbSession, scope: WorkspaceScope) -> list[dict]:
    if scope.role == "viewer":
        raise HTTPException(status_code=403, detail="Workspace access denied")
    return [_runner_out(item) for item in db.scalars(select(RunnerRegistration).where(
        RunnerRegistration.tenant_id == scope.tenant_id, RunnerRegistration.workspace_id == scope.id
    ).order_by(RunnerRegistration.name))]


def _new_credential(db: Session, runner: RunnerRegistration, rotated_from_id: uuid.UUID | None = None) -> str:
    value, digest = issue_runner_token()
    db.add(RunnerCredential(
        runner_id=runner.id,
        token_hash=digest,
        expires_at=datetime.now(UTC) + timedelta(hours=get_settings().runner_credential_hours),
        rotated_from_id=rotated_from_id,
    ))
    return value


@router.post("/runners", status_code=201)
def create_runner(body: RunnerIn, db: DbSession, scope: WorkspaceScope) -> dict:
    _require(scope, ADMIN_ROLES)
    item = RunnerRegistration(
        tenant_id=scope.tenant_id, workspace_id=scope.id,
        name=body.name, capabilities=sorted(set(body.capabilities)),
    )
    db.add(item)
    try:
        db.flush()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Runner name already exists") from None
    credential = _new_credential(db, item)
    return {**_runner_out(item), "credential": credential, "credential_returned_once": True}


@router.post("/runners/{runner_id}/rotate")
def rotate_runner(runner_id: uuid.UUID, db: DbSession, scope: WorkspaceScope) -> dict:
    _require(scope, ADMIN_ROLES)
    runner = db.scalar(select(RunnerRegistration).where(
        RunnerRegistration.id == runner_id, RunnerRegistration.tenant_id == scope.tenant_id,
        RunnerRegistration.workspace_id == scope.id, RunnerRegistration.status == "active",
    ))
    if runner is None:
        raise HTTPException(status_code=404, detail="Runner not found")
    now = datetime.now(UTC)
    old = list(db.scalars(select(RunnerCredential).where(
        RunnerCredential.runner_id == runner.id, RunnerCredential.revoked_at.is_(None)
    )))
    for credential in old:
        credential.revoked_at = now
    value = _new_credential(db, runner, old[-1].id if old else None)
    return {"id": str(runner.id), "credential": value, "credential_returned_once": True}


@router.post("/runners/{runner_id}/revoke")
def revoke_runner(runner_id: uuid.UUID, db: DbSession, scope: WorkspaceScope) -> dict:
    _require(scope, ADMIN_ROLES)
    runner = db.scalar(select(RunnerRegistration).where(
        RunnerRegistration.id == runner_id, RunnerRegistration.tenant_id == scope.tenant_id,
        RunnerRegistration.workspace_id == scope.id,
    ))
    if runner is None:
        raise HTTPException(status_code=404, detail="Runner not found")
    now = datetime.now(UTC)
    runner.status, runner.revoked_at = "revoked", now
    for credential in db.scalars(select(RunnerCredential).where(
        RunnerCredential.runner_id == runner.id, RunnerCredential.revoked_at.is_(None)
    )):
        credential.revoked_at = now
    return _runner_out(runner)


@router.post("/instances", status_code=201)
def create_connector(body: ConnectorIn, db: DbSession, scope: WorkspaceScope) -> dict:
    _require(scope, ADMIN_ROLES)
    if body.runner_id and db.scalar(select(RunnerRegistration.id).where(
        RunnerRegistration.id == body.runner_id, RunnerRegistration.tenant_id == scope.tenant_id,
        RunnerRegistration.workspace_id == scope.id,
    )) is None:
        raise HTTPException(status_code=404, detail="Runner not found")
    _require_bounded(body.configuration, "Connector configuration")
    try:
        maturity, configuration = accepted_instance(
            connector_key=body.connector_key, mode=body.mode, maturity=body.maturity,
            configuration=body.configuration, runner_id=body.runner_id,
            secret_reference_id=body.secret_reference_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if body.secret_reference_id and db.scalar(select(SecretReference.id).where(
        SecretReference.id == body.secret_reference_id, SecretReference.tenant_id == scope.tenant_id,
        SecretReference.workspace_id == scope.id,
    )) is None:
        raise HTTPException(status_code=404, detail="Secret reference not found")
    payload = body.model_dump()
    payload["maturity"] = maturity
    payload["configuration"] = configuration
    item = ConnectorInstance(
        tenant_id=scope.tenant_id, workspace_id=scope.id, status="enabled",
        **payload,
    )
    db.add(item)
    try:
        db.flush()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Connector name already exists") from None
    return _connector_out(item, scope)


@router.get("/instances")
def list_connectors(db: DbSession, scope: WorkspaceScope) -> list[dict]:
    return [_connector_out(item, scope) for item in db.scalars(select(ConnectorInstance).where(
        ConnectorInstance.tenant_id == scope.tenant_id, ConnectorInstance.workspace_id == scope.id
    ).order_by(ConnectorInstance.name))]


@router.post("/jobs", status_code=201)
def enqueue_job(body: JobIn, db: DbSession, scope: WorkspaceScope) -> dict:
    _require(scope, WRITE_ROLES)
    if get_settings().kill_switch:
        raise HTTPException(status_code=503, detail="Connector execution is disabled")
    connector = db.scalar(select(ConnectorInstance).where(
        ConnectorInstance.id == body.connector_instance_id,
        ConnectorInstance.tenant_id == scope.tenant_id,
        ConnectorInstance.workspace_id == scope.id,
        ConnectorInstance.status == "enabled",
    ))
    if connector is None:
        raise HTTPException(status_code=404, detail="Connector instance not found")
    existing = db.scalar(select(ConnectorJob).where(
        ConnectorJob.workspace_id == scope.id, ConnectorJob.idempotency_key == body.idempotency_key
    ))
    if existing:
        return _job_out(existing)
    try:
        accepted_job_input(connector.connector_key, body.input)
    except ValueError as exc:
        if connector.connector_key == "junos.device":
            db.add(AuditEvent(
                entity_type="connector",
                entity_id=connector.id,
                action="rpc_rejected",
                actor=scope.subject[:200],
                payload={"rejected": True},
            ))
            db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from None
    _require_bounded(body.input, "Job input")
    item = ConnectorJob(
        tenant_id=scope.tenant_id, workspace_id=scope.id,
        runner_id=connector.runner_id, created_by=scope.subject, **body.model_dump(),
    )
    db.add(item)
    db.flush()
    add_audit(db, item, "enqueued", scope.subject, {"job_type": item.job_type})
    return _job_out(item)


@router.get("/jobs")
def list_jobs(db: DbSession, scope: WorkspaceScope, limit: int = Query(default=100, ge=1, le=200)) -> list[dict]:
    hide = scope.role == "viewer"
    return [_job_out(item, include_input=not hide, hide_runner=hide) for item in db.scalars(select(ConnectorJob).where(
        ConnectorJob.tenant_id == scope.tenant_id, ConnectorJob.workspace_id == scope.id
    ).order_by(ConnectorJob.created_at.desc()).limit(limit))]


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: uuid.UUID, db: DbSession, scope: WorkspaceScope) -> dict:
    _require(scope, WRITE_ROLES)
    item = db.scalar(select(ConnectorJob).where(
        ConnectorJob.id == job_id, ConnectorJob.tenant_id == scope.tenant_id,
        ConnectorJob.workspace_id == scope.id,
    ))
    if item is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if item.status not in {"succeeded", "failed", "cancelled", "dead_letter"}:
        item.cancel_requested_at = datetime.now(UTC)
        if item.status in {"queued", "retry_wait"}:
            item.status, item.finished_at = "cancelled", item.cancel_requested_at
        add_audit(db, item, "cancellation_requested", scope.subject)
    return _job_out(item)


@router.get("/jobs/{job_id}/audit")
def job_audit(job_id: uuid.UUID, db: DbSession, scope: WorkspaceScope) -> list[dict]:
    exists = db.scalar(select(ConnectorJob.id).where(
        ConnectorJob.id == job_id, ConnectorJob.tenant_id == scope.tenant_id,
        ConnectorJob.workspace_id == scope.id,
    ))
    if exists is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return [{"action": item.action, "actor": item.actor, "at": item.at, "payload": redact(item.payload)}
            for item in db.scalars(select(ConnectorJobAudit).where(
                ConnectorJobAudit.job_id == job_id, ConnectorJobAudit.tenant_id == scope.tenant_id,
                ConnectorJobAudit.workspace_id == scope.id,
            ).order_by(ConnectorJobAudit.at))]


def runner_auth(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> RunnerRegistration:
    prefix = "Bearer "
    if not authorization or not authorization.startswith(prefix):
        raise HTTPException(status_code=401, detail="Runner authentication required")
    runner = authenticate_runner(db, authorization[len(prefix):].strip())
    if runner is None:
        raise HTTPException(status_code=401, detail="Runner authentication required")
    return runner


Runner = Annotated[RunnerRegistration, Depends(runner_auth)]


def _runner_job(db: Session, runner: RunnerRegistration, job_id: uuid.UUID) -> ConnectorJob:
    item = db.scalar(select(ConnectorJob).where(
        ConnectorJob.id == job_id, ConnectorJob.tenant_id == runner.tenant_id,
        ConnectorJob.workspace_id == runner.workspace_id,
        ConnectorJob.runner_id == runner.id,
    ))
    if item is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return item


@runner_router.post("/claim")
def runner_claim(db: DbSession, runner: Runner) -> dict | None:
    if get_settings().kill_switch:
        raise HTTPException(status_code=503, detail="Connector execution is disabled")
    item = claim_job(
        db, get_settings(), owner=f"runner:{runner.id}", runner_id=runner.id,
        workspace_id=runner.workspace_id, tenant_id=runner.tenant_id,
    )
    if item is None:
        return None
    output = _job_out(item)
    output["dispatch"] = _dispatch(db, item)
    return output


def _dispatch(db: Session, item: ConnectorJob) -> dict | None:
    connector = db.get(ConnectorInstance, item.connector_instance_id)
    if connector is None or connector.tenant_id != item.tenant_id or connector.workspace_id != item.workspace_id:
        return None
    locator = None
    if connector.secret_reference_id is not None:
        reference = db.get(SecretReference, connector.secret_reference_id)
        if reference is not None and reference.tenant_id == item.tenant_id and reference.workspace_id == item.workspace_id:
            locator = reference.locator
    return {
        "connector_key": connector.connector_key,
        "mode": connector.mode,
        "configuration": redact(connector.configuration),
        "secret_locator": locator,
        "tenant_id": str(item.tenant_id),
        "workspace_id": str(item.workspace_id),
    }


@runner_router.post("/jobs/{job_id}/progress")
def runner_progress(job_id: uuid.UUID, body: ProgressIn, db: DbSession, runner: Runner) -> dict:
    if get_settings().kill_switch:
        raise HTTPException(status_code=503, detail="Connector execution is disabled")
    item = _runner_job(db, runner, job_id)
    _require_lease(item, runner)
    if payload_too_large(body.progress):
        raise HTTPException(status_code=422, detail="Job progress exceeds 64 KiB")
    if item.cancel_requested_at:
        raise HTTPException(status_code=409, detail="Job cancellation requested")
    if item.status not in {"leased", "running"}:
        raise HTTPException(status_code=409, detail="Job is not active")
    item.status, item.progress = "running", redact(body.progress)
    item.lease_expires_at = datetime.now(UTC) + timedelta(seconds=get_settings().connector_lease_seconds)
    add_audit(db, item, "progress", f"runner:{runner.id}", item.progress)
    return _job_out(item)


@runner_router.post("/jobs/{job_id}/complete")
def runner_complete(job_id: uuid.UUID, body: CollectionEnvelope, db: DbSession, runner: Runner) -> dict:
    if get_settings().kill_switch:
        raise HTTPException(status_code=503, detail="Connector execution is disabled")
    item = _runner_job(db, runner, job_id)
    _require_lease(item, runner)
    if len(body.model_dump_json().encode()) > 1_048_576:
        raise HTTPException(status_code=422, detail="Envelope exceeds 1 MiB")
    if body.job_id != str(item.id) or body.idempotency_key != item.idempotency_key:
        raise HTTPException(status_code=409, detail="Envelope does not match job")
    if body.content_hash != CollectionEnvelope.hash_records(body.records):
        raise HTTPException(status_code=422, detail="Envelope content hash is invalid")
    complete_job(db, item, f"runner:{runner.id}", body.model_dump(mode="json"))
    return _job_out(item)


@runner_router.post("/jobs/{job_id}/fail")
def runner_fail(job_id: uuid.UUID, body: FailureIn, db: DbSession, runner: Runner) -> dict:
    item = _runner_job(db, runner, job_id)
    _require_lease(item, runner)
    fail_job(db, item, f"runner:{runner.id}", body.code, body.detail, retryable=body.retryable)
    return _job_out(item)


@runner_router.post("/health")
def runner_health(body: HealthIn, db: DbSession, runner: Runner) -> dict:
    item = db.scalar(select(ConnectorInstance).where(
        ConnectorInstance.id == body.connector_instance_id,
        ConnectorInstance.tenant_id == runner.tenant_id,
        ConnectorInstance.workspace_id == runner.workspace_id,
        ConnectorInstance.runner_id == runner.id,
    ))
    if item is None:
        raise HTTPException(status_code=404, detail="Connector instance not found")
    item.health_state = body.health.state
    item.health_detail = body.health.detail
    item.last_health_at = body.health.checked_at
    return _connector_out(item, SimpleNamespace(role="operator"))
