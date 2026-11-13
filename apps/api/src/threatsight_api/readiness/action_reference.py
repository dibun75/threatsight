"""Idempotent Phase 3B accountable-action reference journeys."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import Identity, Workspace, WorkspaceMembership
from threatsight_api.persistence.readiness_models import (
    ReadinessAction,
    ReadinessDecision,
    ReadinessRecommendation,
    ReadinessVerificationRequest,
)
from threatsight_api.readiness.actions import (
    assign,
    close,
    ensure_action_for_decision,
    reopen,
    satisfy_requirement,
)
from threatsight_api.readiness.engine import ensure_policy, recommend_for_workspace
from threatsight_api.readiness.service import approve, decide


def install(connection) -> None:
    session = Session(bind=connection)
    try:
        workspaces = list(session.scalars(select(Workspace).where(Workspace.status == "active")))
        for workspace in workspaces:
            policy = ensure_policy(session, workspace.tenant_id, workspace.id)
            if policy.kill_switch:
                continue
            _install_workspace(session, workspace)
        session.commit()
    finally:
        session.close()


def _install_workspace(db: Session, workspace: Workspace) -> None:
    recommend_for_workspace(db, workspace.tenant_id, workspace.id, actor="migration:0026")
    owner = _synthetic_owner(db, workspace, "ready-owner-ordering")
    reviewer = _synthetic_owner(db, workspace, "ready-reviewer-ordering")
    admin_subject = reviewer.subject
    # Ensure recommendations exist, then drive journeys.
    recs = {
        row.service_source_key: row
        for row in db.scalars(
            select(ReadinessRecommendation).where(
                ReadinessRecommendation.workspace_id == workspace.id,
                ReadinessRecommendation.state.in_(("candidate", "approved")),
            )
        )
    }
    ordering = recs.get("synthetic.fixture:service:customer-ordering")
    privileged = recs.get("synthetic.fixture:service:privileged-administration")
    remote = recs.get("synthetic.fixture:service:remote-access")
    if ordering is not None:
        _customer_ordering(db, workspace, ordering, owner, admin_subject)
    if privileged is not None:
        _privileged(db, workspace, privileged, owner, admin_subject)
    if remote is not None:
        _remote(db, workspace, remote, owner, admin_subject)


def _customer_ordering(db: Session, workspace: Workspace, recommendation: ReadinessRecommendation, owner: Identity, actor: str) -> None:
    request = _ensure_verified(db, workspace, recommendation, actor)
    decision = _ensure_decision(db, workspace, request, actor, "accepted")
    action = ensure_action_for_decision(db, workspace.tenant_id, workspace.id, decision, actor=actor)
    if action.status == "open":
        assign(db, workspace.tenant_id, workspace.id, action.id, owner.id, actor, "workspace-admin", due_at=datetime.now(UTC) + timedelta(days=7))
        action = db.get(ReadinessAction, action.id)
    if action is not None and action.status in {"assigned", "in_progress", "awaiting_evidence", "ready_for_review"}:
        from threatsight_api.persistence.readiness_models import ReadinessClosureRequirement

        requirements = list(
            db.scalars(
                select(ReadinessClosureRequirement).where(
                    ReadinessClosureRequirement.action_id == action.id,
                    ReadinessClosureRequirement.status == "pending",
                )
            )
        )
        for requirement in requirements:
            satisfy_requirement(
                db,
                workspace.tenant_id,
                workspace.id,
                action.id,
                requirement.id,
                actor,
                "workspace-admin",
                evidence_id=action.evidence_id,
            )
        action = db.get(ReadinessAction, action.id)
    if action is not None and action.status == "ready_for_review":
        close(
            db,
            workspace.tenant_id,
            workspace.id,
            action.id,
            "resolved_by_evidence",
            "Reference installed-version evidence reviewed. This is not compliance certification.",
            actor,
            "workspace-admin",
        )
        action = db.get(ReadinessAction, action.id)
    if action is not None and action.status == "reopened":
        from threatsight_api.signing.reference import ensure_closed_for_reference_signature

        ensure_closed_for_reference_signature(db, workspace, action, actor)
        action = db.get(ReadinessAction, action.id)
    if action is not None and action.status == "closed":
        from threatsight_api.signing.reference import ensure_reference_signature

        ensure_reference_signature(db, workspace, action, actor)
        action = db.get(ReadinessAction, action.id)
    # Reopen only after a signature exists so the prior signature becomes valid_superseded.
    # Clear a stale reopen_after_sign flag left from unsigned closure demos.
    if action is not None:
        from threatsight_api.persistence.signing_models import EvidenceSignature

        prior_sig = db.scalar(
            select(EvidenceSignature).where(
                EvidenceSignature.action_id == action.id,
                EvidenceSignature.workspace_id == workspace.id,
            )
        )
        meta = dict(action.metadata_safe or {})
        if prior_sig is None and meta.get("reopen_after_sign") == "done":
            meta.pop("reopen_after_sign", None)
            action.metadata_safe = meta
            db.flush()
        if (
            action.status == "closed"
            and prior_sig is not None
            and meta.get("reopen_after_sign") != "done"
        ):
            reopen(
                db,
                workspace.tenant_id,
                workspace.id,
                action.id,
                "Reference evidence hash changed after closure.",
                actor,
                "workspace-admin",
                new_evidence_hash="changed-reference-hash",
            )
            action = db.get(ReadinessAction, action.id)
            if action is not None:
                action.metadata_safe = {**(action.metadata_safe or {}), "reopen_demo": "done", "reopen_after_sign": "done"}
                db.flush()


def _privileged(db: Session, workspace: Workspace, recommendation: ReadinessRecommendation, owner: Identity, actor: str) -> None:
    request = _ensure_verified(db, workspace, recommendation, actor)
    decision = _ensure_decision(db, workspace, request, actor, "needs_more_data")
    action = ensure_action_for_decision(db, workspace.tenant_id, workspace.id, decision, actor=actor)
    if action.status == "open":
        assign(db, workspace.tenant_id, workspace.id, action.id, owner.id, actor, "workspace-admin", due_at=datetime.now(UTC) + timedelta(days=3))
        action = db.get(ReadinessAction, action.id)
    if action is not None and action.status == "assigned":
        from threatsight_api.readiness.actions import transition

        transition(db, workspace.tenant_id, workspace.id, action.id, "awaiting_evidence", actor, "workspace-admin")


def _remote(db: Session, workspace: Workspace, recommendation: ReadinessRecommendation, owner: Identity, actor: str) -> None:
    request = _ensure_verified(db, workspace, recommendation, actor)
    decision = _ensure_decision(db, workspace, request, actor, "needs_more_data")
    action = ensure_action_for_decision(db, workspace.tenant_id, workspace.id, decision, actor=actor)
    if action.status == "open":
        assign(db, workspace.tenant_id, workspace.id, action.id, owner.id, actor, "workspace-admin", due_at=datetime.now(UTC) + timedelta(days=14))
        action = db.get(ReadinessAction, action.id)
    if action is not None and action.status == "assigned":
        from threatsight_api.readiness.actions import transition

        transition(db, workspace.tenant_id, workspace.id, action.id, "awaiting_evidence", actor, "workspace-admin")
        # Do not satisfy requirements — closure must remain blocked.


def _ensure_verified(db: Session, workspace: Workspace, recommendation: ReadinessRecommendation, actor: str) -> ReadinessVerificationRequest:
    existing = db.scalar(
        select(ReadinessVerificationRequest).where(
            ReadinessVerificationRequest.workspace_id == workspace.id,
            ReadinessVerificationRequest.recommendation_id == recommendation.id,
        )
    )
    if existing is not None:
        return existing
    body = approve(db, workspace.tenant_id, workspace.id, recommendation.id, actor, "workspace-admin")
    return db.get(ReadinessVerificationRequest, uuid.UUID(body["id"]))


def _ensure_decision(db: Session, workspace: Workspace, request: ReadinessVerificationRequest, actor: str, outcome: str) -> ReadinessDecision:
    existing = db.scalar(
        select(ReadinessDecision).where(
            ReadinessDecision.workspace_id == workspace.id,
            ReadinessDecision.request_id == request.id,
        )
    )
    if existing is not None:
        return existing
    body = decide(db, workspace.tenant_id, workspace.id, request.id, outcome, f"Reference decision: {outcome}.", actor, "workspace-admin")
    return db.get(ReadinessDecision, uuid.UUID(body["id"]))


def _synthetic_owner(db: Session, workspace: Workspace, subject: str) -> Identity:
    identity = db.scalar(select(Identity).where(Identity.issuer == "synthetic-reference", Identity.subject == subject))
    if identity is None:
        identity = Identity(
            issuer="synthetic-reference",
            subject=subject,
            display_name=f"Synthetic {subject}",
            email=None,
            status="active",
        )
        db.add(identity)
        db.flush()
    membership = db.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.subject == subject,
        )
    )
    if membership is None:
        db.add(
            WorkspaceMembership(
                workspace_id=workspace.id,
                subject=subject,
                identity_id=identity.id,
                role="operator",
            )
        )
        db.flush()
    elif membership.identity_id is None:
        membership.identity_id = identity.id
        db.flush()
    return identity
