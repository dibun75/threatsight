from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from threatsight_api.config import Settings
from threatsight_api.persistence.models import (
    ConnectorJob,
    ConnectorJobAttempt,
    ConnectorJobAudit,
    RunnerCredential,
    RunnerRegistration,
    Workspace,
)

MAX_TOKEN_LENGTH = 512
MAX_PAYLOAD_BYTES = 65_536

TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled", "dead_letter"})
SECRET_KEYS = frozenset({"secret", "token", "password", "credential", "api_key", "private_key", "authorization"})


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hashes_match(stored: str, presented: str) -> bool:
    if len(stored) != len(presented):
        return False
    return hmac.compare_digest(stored.encode(), presented.encode())


def payload_too_large(value: Any, limit: int = MAX_PAYLOAD_BYTES) -> bool:
    try:
        encoded = json.dumps(value, default=str, separators=(",", ":")).encode()
    except (TypeError, ValueError):
        return True
    return len(encoded) > limit


def issue_runner_token() -> tuple[str, str]:
    value = "tsr_" + secrets.token_urlsafe(32)
    return value, token_hash(value)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if str(key).lower() in SECRET_KEYS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def contains_secret_material(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in SECRET_KEYS or contains_secret_material(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(contains_secret_material(item) for item in value)
    return False


def backoff_seconds(attempt: int, maximum: int = 900) -> int:
    return min(maximum, 2 ** min(max(1, attempt), 10))


def add_audit(db: Session, job: ConnectorJob, action: str, actor: str, payload: dict | None = None) -> None:
    db.add(ConnectorJobAudit(
        tenant_id=job.tenant_id,
        workspace_id=job.workspace_id,
        job_id=job.id,
        action=action,
        actor=actor[:200],
        payload=redact(payload or {}),
    ))


def _claim_filter(now: datetime):
    waiting = and_(
        ConnectorJob.status.in_(("queued", "retry_wait")),
        ConnectorJob.available_at <= now,
        ConnectorJob.cancel_requested_at.is_(None),
    )
    expired = and_(
        ConnectorJob.status.in_(("leased", "running")),
        ConnectorJob.lease_expires_at.is_not(None),
        ConnectorJob.lease_expires_at <= now,
    )
    return or_(waiting, expired)


def _scope_claim(statement, *, runner_id, workspace_id, tenant_id, local_only: bool):
    if runner_id is not None:
        statement = statement.where(ConnectorJob.runner_id == runner_id)
    elif local_only:
        statement = statement.where(ConnectorJob.runner_id.is_(None))
    if workspace_id is not None:
        statement = statement.where(ConnectorJob.workspace_id == workspace_id)
    if tenant_id is not None:
        statement = statement.where(ConnectorJob.tenant_id == tenant_id)
    return statement


def claim_job(
    db: Session,
    settings: Settings,
    *,
    owner: str,
    runner_id: uuid.UUID | None = None,
    workspace_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    local_only: bool = False,
    now: datetime | None = None,
) -> ConnectorJob | None:
    if settings.kill_switch:
        return None
    now = now or datetime.now(UTC)
    claimable = _claim_filter(now)
    if workspace_id is None:
        workspace_id = db.scalar(
            _scope_claim(
                select(ConnectorJob.workspace_id).where(claimable),
                runner_id=runner_id,
                workspace_id=None,
                tenant_id=tenant_id,
                local_only=local_only,
            ).order_by(ConnectorJob.priority, ConnectorJob.created_at).limit(1)
        )
        if workspace_id is None:
            return None
    locked = db.scalar(select(Workspace.id).where(Workspace.id == workspace_id).with_for_update())
    if locked is None:
        return None
    active = db.scalar(
        select(func.count())
        .select_from(ConnectorJob)
        .where(
            ConnectorJob.workspace_id == workspace_id,
            ConnectorJob.status.in_(("leased", "running")),
            ConnectorJob.lease_expires_at > now,
        )
    ) or 0
    if active >= settings.connector_workspace_concurrency:
        return None
    job = db.scalar(
        _scope_claim(
            select(ConnectorJob).where(claimable, ConnectorJob.workspace_id == workspace_id),
            runner_id=runner_id,
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            local_only=local_only,
        )
        .order_by(ConnectorJob.priority, ConnectorJob.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if job is None:
        return None
    if job.cancel_requested_at is not None or job.attempt_count >= job.max_attempts:
        job.status = "cancelled" if job.cancel_requested_at is not None else "dead_letter"
        job.finished_at = now
        job.lease_owner = None
        job.lease_expires_at = None
        add_audit(db, job, job.status, owner, {"attempt": job.attempt_count})
        return None
    job.status = "leased"
    job.lease_owner = owner[:200]
    job.lease_expires_at = now + timedelta(seconds=settings.connector_lease_seconds)
    job.attempt_count += 1
    job.started_at = job.started_at or now
    db.add(ConnectorJobAttempt(
        job_id=job.id,
        attempt_number=job.attempt_count,
        runner_id=runner_id,
        status="leased",
    ))
    add_audit(db, job, "claimed", owner, {"attempt": job.attempt_count})
    return job


def complete_job(db: Session, job: ConnectorJob, actor: str, envelope: dict, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    if job.cancel_requested_at is not None:
        job.status = "cancelled"
    else:
        job.status = "succeeded"
    job.finished_at = now
    job.lease_owner = None
    job.lease_expires_at = None
    attempt = db.scalar(select(ConnectorJobAttempt).where(
        ConnectorJobAttempt.job_id == job.id,
        ConnectorJobAttempt.attempt_number == job.attempt_count,
    ))
    if attempt:
        attempt.status = job.status
        attempt.finished_at = now
        attempt.result_envelope = redact(envelope)
    add_audit(db, job, job.status, actor, {"progress": job.progress})


def fail_job(
    db: Session,
    job: ConnectorJob,
    actor: str,
    code: str,
    detail: str,
    *,
    retryable: bool = True,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    raw_detail = str(detail or "")
    if "<" in raw_detail or ">" in raw_detail or "BEGIN " in raw_detail or "PRIVATE KEY" in raw_detail:
        safe_detail = str(code)[:64]
    else:
        safe_detail = " ".join(str(redact(raw_detail)).split())[:500]
    job.last_error_code = code[:64]
    job.last_error_detail = safe_detail
    job.lease_owner = None
    job.lease_expires_at = None
    if job.cancel_requested_at is not None:
        job.status = "cancelled"
        job.finished_at = now
    elif retryable and job.attempt_count < job.max_attempts:
        job.status = "retry_wait"
        job.available_at = now + timedelta(seconds=backoff_seconds(job.attempt_count))
    else:
        job.status = "dead_letter" if job.attempt_count >= job.max_attempts else "failed"
        job.finished_at = now
    attempt = db.scalar(select(ConnectorJobAttempt).where(
        ConnectorJobAttempt.job_id == job.id,
        ConnectorJobAttempt.attempt_number == job.attempt_count,
    ))
    if attempt:
        attempt.status = job.status
        attempt.finished_at = now
        attempt.error_code = job.last_error_code
        attempt.error_detail = safe_detail
    add_audit(db, job, job.status, actor, {"error_code": job.last_error_code, "error_detail": safe_detail})


def authenticate_runner(db: Session, token: str, now: datetime | None = None) -> RunnerRegistration | None:
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return None
    now = now or datetime.now(UTC)
    presented = token_hash(token)
    credential = db.scalar(select(RunnerCredential).where(RunnerCredential.token_hash == presented))
    if credential is None or not hashes_match(credential.token_hash, presented):
        return None
    if credential.revoked_at is not None or credential.expires_at <= now:
        return None
    runner = db.get(RunnerRegistration, credential.runner_id)
    if runner is None or runner.status != "active" or runner.revoked_at is not None:
        return None
    credential.last_used_at = now
    runner.last_seen_at = now
    return runner
