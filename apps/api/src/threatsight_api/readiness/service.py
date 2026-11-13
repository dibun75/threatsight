"""Read and mutate readiness objects with approval and fixture execution."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import ConnectorJob, EvidenceRecord
from threatsight_api.integrations import alerts
from threatsight_api.persistence.readiness_models import (
    ReadinessAudit,
    ReadinessDecision,
    ReadinessEvidenceLink,
    ReadinessRecommendation,
    ReadinessResult,
    ReadinessVerificationRequest,
)
from threatsight_api.presentation import public_name
from threatsight_api.readiness.checks import require_check
from threatsight_api.readiness.engine import ensure_policy, recommend_for_workspace
from threatsight_api.readiness.vocabulary import APPROVE_ROLES, DECISION_OUTCOMES, REVIEW_ROLES

_NOT_FOUND = "Readiness object not found"


def summary(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID) -> dict:
    ensure_policy(db, tenant_id, workspace_id)
    recommend_for_workspace(db, tenant_id, workspace_id)
    rows = list(
        db.scalars(
            select(ReadinessRecommendation).where(
                ReadinessRecommendation.tenant_id == tenant_id,
                ReadinessRecommendation.workspace_id == workspace_id,
                ReadinessRecommendation.state.in_(("candidate", "approved", "needs_more_data")),
            )
        )
    )
    items = [_recommendation_out(db, row) for row in rows]
    return {
        "approval_mode": "manual_approval_required",
        "services_needing_verification": len({item["service_source_key"] for item in items}),
        "recommendations": items,
        "does_not_mean": "A recommendation is not a control failure, compromise, or compliance result.",
    }


def list_recommendations(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, *, state: str | None = None, service: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    stmt = select(ReadinessRecommendation).where(
        ReadinessRecommendation.tenant_id == tenant_id,
        ReadinessRecommendation.workspace_id == workspace_id,
    )
    if state:
        stmt = stmt.where(ReadinessRecommendation.state == state)
    if service:
        stmt = stmt.where(ReadinessRecommendation.service_source_key == service)
    rows = list(db.scalars(stmt.order_by(ReadinessRecommendation.created_at.desc()).offset(offset).limit(limit)))
    return {"items": [_recommendation_out(db, row) for row in rows], "count": len(rows)}


def get_recommendation(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, recommendation_id: uuid.UUID) -> dict:
    row = _recommendation(db, tenant_id, workspace_id, recommendation_id)
    return _recommendation_out(db, row, detail=True)


def preview(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, recommendation_id: uuid.UUID, actor: str, role: str) -> dict:
    _require_review(role)
    row = _recommendation(db, tenant_id, workspace_id, recommendation_id)
    check = require_check(row.check_id)
    _audit(db, tenant_id, workspace_id, "recommendation", row.id, "preview", actor, {"check_id": check.id})
    db.flush()
    return {
        "recommendation_id": str(row.id),
        "state": row.state,
        "why": row.rationale,
        "service": public_name(row.service_source_key),
        "service_source_key": row.service_source_key,
        "technology": public_name(row.asset_source_key or ""),
        "control": row.control_title,
        "exact_check": {"id": check.id, "version": check.version, "title": check.title},
        "expected_data": check.expected_data,
        "permissions_required": "workspace or platform administrator approval",
        "runner_destination": "workspace fixture runner" if not check.live_supported else "assigned workspace runner",
        "secret_reference": "runner-local reference only" if check.secret_reference_required else "not required",
        "operational_impact": check.operational_impact,
        "timeout_seconds": 120,
        "evidence_needed": check.expected_data,
        "cancellation": "Cancellation stops a queued or leased job. A completed result is preserved.",
        "maturity": "Validated with reference data",
        "limitations": list(check.limitations),
        "approval_required": True,
        "does_not_mean": "Preview does not execute a check and does not change infrastructure.",
    }


def approve(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, recommendation_id: uuid.UUID, actor: str, role: str) -> dict:
    _require_approve(role)
    policy = ensure_policy(db, tenant_id, workspace_id)
    if policy.kill_switch or policy.approval_mode != "manual_approval_required":
        if policy.kill_switch:
            raise HTTPException(status_code=409, detail="Kill switch is active")
    row = _recommendation(db, tenant_id, workspace_id, recommendation_id)
    if row.state in {"dismissed", "superseded"}:
        raise HTTPException(status_code=409, detail="Recommendation is no longer actionable")
    if row.state == "approved":
        existing = db.scalar(
            select(ReadinessVerificationRequest).where(
                ReadinessVerificationRequest.workspace_id == workspace_id,
                ReadinessVerificationRequest.recommendation_id == row.id,
            )
        )
        if existing is not None:
            return _request_out(db, existing)
    check = require_check(row.check_id)
    _assert_reference_execution_allowed(check)
    idempotency = f"verify:{row.id}:{row.evidence_hash[:16]}"
    existing = db.scalar(
        select(ReadinessVerificationRequest).where(
            ReadinessVerificationRequest.workspace_id == workspace_id,
            ReadinessVerificationRequest.idempotency_key == idempotency,
        )
    )
    if existing is not None:
        return _request_out(db, existing)
    count = len(
        list(
            db.scalars(
                select(ReadinessVerificationRequest).where(
                    ReadinessVerificationRequest.workspace_id == workspace_id,
                    ReadinessVerificationRequest.status.in_(("approved", "queued", "running", "succeeded")),
                )
            )
        )
    )
    if count >= policy.max_executions_per_workspace:
        raise HTTPException(status_code=409, detail="Workspace execution limit reached")
    now = datetime.now(UTC)
    request = ReadinessVerificationRequest(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        recommendation_id=row.id,
        request_type="read_only_connector",
        status="approved",
        check_id=check.id,
        check_version=check.version,
        approved_by=actor,
        approved_at=now,
        expected_data=check.expected_data[:500],
        operational_impact=check.operational_impact[:500],
        maturity="fixture_tested",
        idempotency_key=idempotency,
        metadata_safe={"mode": "fixture_tested"},
    )
    db.add(request)
    row.state = "approved"
    row.version += 1
    db.flush()
    _audit(db, tenant_id, workspace_id, "verification_request", request.id, "approved", actor, {"check_id": check.id})
    _run_fixture(db, request, actor)
    db.flush()
    return _request_out(db, request)


def dismiss(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, recommendation_id: uuid.UUID, actor: str, role: str) -> dict:
    _require_approve(role)
    row = _recommendation(db, tenant_id, workspace_id, recommendation_id)
    if row.state in {"superseded"}:
        raise HTTPException(status_code=409, detail="Recommendation is already superseded")
    row.state = "dismissed"
    row.version += 1
    _audit(db, tenant_id, workspace_id, "recommendation", row.id, "dismissed", actor, {})
    db.flush()
    return _recommendation_out(db, row)


def decide(
    db: Session,
    tenant_id: uuid.UUID,
    workspace_id: uuid.UUID,
    request_id: uuid.UUID,
    outcome: str,
    rationale: str,
    actor: str,
    role: str,
) -> dict:
    _require_approve(role)
    if outcome not in DECISION_OUTCOMES:
        raise HTTPException(status_code=400, detail="Unsupported decision outcome")
    request = _request(db, tenant_id, workspace_id, request_id)
    result = db.scalar(
        select(ReadinessResult)
        .where(ReadinessResult.request_id == request.id, ReadinessResult.workspace_id == workspace_id)
        .order_by(ReadinessResult.created_at.desc())
    )
    decision = ReadinessDecision(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        request_id=request.id,
        result_id=None if result is None else result.id,
        outcome=outcome,
        actor=actor,
        rationale=rationale[:1000],
    )
    db.add(decision)
    db.flush()
    _audit(db, tenant_id, workspace_id, "decision", decision.id, "recorded", actor, {"outcome": outcome})
    action_id = None
    if outcome in {"accepted", "remediation_required", "needs_more_data", "risk_accepted"}:
        from threatsight_api.readiness.actions import ensure_action_for_decision

        action = ensure_action_for_decision(db, tenant_id, workspace_id, decision, actor=actor)
        action_id = str(action.id)
    db.flush()
    return {
        "id": str(decision.id),
        "outcome": decision.outcome,
        "actor": decision.actor,
        "rationale": decision.rationale,
        "action_id": action_id,
        "does_not_mean": "A human decision is not compliance certification or proof of control effectiveness.",
    }


def get_request(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, request_id: uuid.UUID) -> dict:
    return _request_out(db, _request(db, tenant_id, workspace_id, request_id))


def list_requests(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, *, service: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    stmt = select(ReadinessVerificationRequest).where(
        ReadinessVerificationRequest.tenant_id == tenant_id,
        ReadinessVerificationRequest.workspace_id == workspace_id,
    )
    rows = list(db.scalars(stmt.order_by(ReadinessVerificationRequest.created_at.desc()).offset(offset).limit(limit)))
    items = [_request_out(db, row) for row in rows]
    if service:
        items = [item for item in items if item.get("service_source_key") == service]
    return {"items": items, "count": len(items)}


def _assert_reference_execution_allowed(check) -> None:
    if check.live_supported:
        raise HTTPException(status_code=409, detail="Live verification requires the durable customer-runner path")
    if check.maturity != "fixture_tested":
        raise HTTPException(status_code=409, detail="Only fixture-tested reference checks may execute in-process")


def _run_fixture(db: Session, request: ReadinessVerificationRequest, actor: str) -> None:
    check = require_check(request.check_id)
    _assert_reference_execution_allowed(check)
    job = ConnectorJob(
        tenant_id=request.tenant_id,
        workspace_id=request.workspace_id,
        connector_instance_id=_fixture_connector(db, request),
        job_type=check.id,
        status="succeeded",
        idempotency_key=f"readiness:{request.id}",
        input={"check_id": check.id, "mode": "fixture"},
        progress={"phase": "complete"},
        attempt_count=1,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        created_by=actor,
    )
    db.add(job)
    db.flush()
    request.connector_job_id = job.id
    request.status = "succeeded"
    digest = hashlib.sha256(f"{request.id}:{check.id}:configured_not_observed".encode()).hexdigest()
    result = ReadinessResult(
        tenant_id=request.tenant_id,
        workspace_id=request.workspace_id,
        request_id=request.id,
        connector_job_id=job.id,
        outcome="configured_not_observed",
        check_id=check.id,
        check_version=check.version,
        evidence_hash=digest,
        summary=f"{check.title} completed against reference data. Configuration was recorded. Effectiveness was not observed.",
        limitations=list(check.limitations),
        maturity="fixture_tested",
        freshness="fresh",
        metadata_safe={"defined_check": check.id},
    )
    db.add(result)
    db.flush()
    alerts.notify_result(db, result)
    evidence = EvidenceRecord(
        title=f"Readiness result: {check.title}"[:200],
        evidence_type="manual",
        status="accepted",
        source_reference=f"synthetic-readiness:{request.id}",
        description=result.summary[:2000],
        integrity_hash=digest,
        owner="Unassigned",
    )
    db.add(evidence)
    db.flush()
    db.add(
        ReadinessEvidenceLink(
            tenant_id=request.tenant_id,
            workspace_id=request.workspace_id,
            request_id=request.id,
            result_id=result.id,
            evidence_id=evidence.id,
            relationship="new",
        )
    )
    _audit(db, request.tenant_id, request.workspace_id, "result", result.id, "published", actor, {"outcome": result.outcome})
    _audit(db, request.tenant_id, request.workspace_id, "verification_request", request.id, "completed", actor, {"job_id": str(job.id)})


def _fixture_connector(db: Session, request: ReadinessVerificationRequest) -> uuid.UUID:
    from threatsight_api.persistence.models import ConnectorInstance

    row = db.scalar(
        select(ConnectorInstance).where(
            ConnectorInstance.workspace_id == request.workspace_id,
            ConnectorInstance.connector_key == "synthetic-fixture",
        )
    )
    if row is not None:
        return row.id
    row = ConnectorInstance(
        tenant_id=request.tenant_id,
        workspace_id=request.workspace_id,
        connector_key="synthetic-fixture",
        name="Synthetic fixture connector",
        status="active",
        mode="fixture",
        maturity="fixture_tested",
        configuration={"capabilities": ["inventory", "configuration_evidence", "health"]},
    )
    db.add(row)
    db.flush()
    return row.id


def _recommendation(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, recommendation_id: uuid.UUID) -> ReadinessRecommendation:
    row = db.scalar(
        select(ReadinessRecommendation).where(
            ReadinessRecommendation.id == recommendation_id,
            ReadinessRecommendation.tenant_id == tenant_id,
            ReadinessRecommendation.workspace_id == workspace_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


def _request(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, request_id: uuid.UUID) -> ReadinessVerificationRequest:
    row = db.scalar(
        select(ReadinessVerificationRequest).where(
            ReadinessVerificationRequest.id == request_id,
            ReadinessVerificationRequest.tenant_id == tenant_id,
            ReadinessVerificationRequest.workspace_id == workspace_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return row


def _recommendation_out(db: Session, row: ReadinessRecommendation, *, detail: bool = False) -> dict:
    check = require_check(row.check_id)
    request = db.scalar(
        select(ReadinessVerificationRequest).where(
            ReadinessVerificationRequest.recommendation_id == row.id,
            ReadinessVerificationRequest.workspace_id == row.workspace_id,
        )
    )
    result = None
    decision = None
    if request is not None:
        result = db.scalar(
            select(ReadinessResult)
            .where(ReadinessResult.request_id == request.id, ReadinessResult.workspace_id == row.workspace_id)
            .order_by(ReadinessResult.created_at.desc())
        )
        decision = db.scalar(
            select(ReadinessDecision)
            .where(ReadinessDecision.request_id == request.id, ReadinessDecision.workspace_id == row.workspace_id)
            .order_by(ReadinessDecision.created_at.desc())
        )
    body = {
        "id": str(row.id),
        "state": row.state,
        "service": public_name(row.service_source_key),
        "service_source_key": row.service_source_key,
        "service_node_id": None if row.service_node_id is None else str(row.service_node_id),
        "control": row.control_title,
        "check_id": row.check_id,
        "check_title": check.title,
        "match_classification": row.match_classification,
        "rationale": row.rationale,
        "maturity": "Validated with reference data",
        "approval_required": row.state == "candidate",
        "owner": "Unassigned",
        "next_decision": "Record a human review of the verification result." if request is not None and request.status == "succeeded" and decision is None else "Await approval before execution." if row.state == "candidate" else "No verification decision is pending.",
        "request_id": None if request is None else str(request.id),
        "request_status": None if request is None else request.status,
        "result_outcome": None if result is None else result.outcome,
        "result_summary": None if result is None else result.summary,
        "result_freshness": None if result is None else result.freshness,
        "evidence_hash": None if result is None else result.evidence_hash,
        "decision_outcome": None if decision is None else decision.outcome,
        "limitations": list(check.limitations),
    }
    if detail:
        body["preview"] = {
            "expected_data": check.expected_data,
            "operational_impact": check.operational_impact,
            "limitations": list(check.limitations),
        }
    return body


def _request_out(db: Session, row: ReadinessVerificationRequest) -> dict:
    recommendation = db.get(ReadinessRecommendation, row.recommendation_id)
    result = db.scalar(
        select(ReadinessResult)
        .where(ReadinessResult.request_id == row.id)
        .order_by(ReadinessResult.created_at.desc())
    )
    decisions = list(
        db.scalars(
            select(ReadinessDecision)
            .where(ReadinessDecision.request_id == row.id)
            .order_by(ReadinessDecision.created_at.desc())
        )
    )
    return {
        "id": str(row.id),
        "status": row.status,
        "check_id": row.check_id,
        "check_version": row.check_version,
        "recommendation_id": str(row.recommendation_id),
        "service": None if recommendation is None else public_name(recommendation.service_source_key),
        "service_source_key": None if recommendation is None else recommendation.service_source_key,
        "control": None if recommendation is None else recommendation.control_title,
        "approved_by": row.approved_by,
        "approved_at": None if row.approved_at is None else row.approved_at.isoformat(),
        "maturity": "Validated with reference data",
        "result": None
        if result is None
        else {
            "id": str(result.id),
            "outcome": result.outcome,
            "summary": result.summary,
            "evidence_hash": result.evidence_hash,
            "freshness": result.freshness,
            "limitations": result.limitations,
            "maturity": "Validated with reference data",
        },
        "decisions": [
            {"id": str(item.id), "outcome": item.outcome, "actor": item.actor, "rationale": item.rationale}
            for item in decisions
        ],
        "does_not_mean": "Execution without approval is rejected. A fixture result is not live customer validation.",
    }


def _require_review(role: str) -> None:
    if role not in REVIEW_ROLES:
        raise HTTPException(status_code=403, detail="Review permission required")


def _require_approve(role: str) -> None:
    if role not in APPROVE_ROLES:
        raise HTTPException(status_code=403, detail="Administrator approval required")


def _audit(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, object_type: str, object_id: uuid.UUID, action: str, actor: str, payload: dict) -> None:
    db.add(
        ReadinessAudit(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            object_type=object_type,
            object_id=object_id,
            action=action,
            actor=actor,
            payload=payload,
        )
    )
