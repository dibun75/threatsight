"""Continuous-readiness tables. Execution reuses connector_jobs."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatsight_api.persistence.models import Base, TimestampMixin


class ReadinessPolicy(TimestampMixin, Base):
    __tablename__ = "readiness_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    approval_mode: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'manual_approval_required'"))
    kill_switch: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    max_recommendations_per_trigger: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("20"))
    max_executions_per_workspace: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("50"))
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))

    __table_args__ = (UniqueConstraint("workspace_id", name="uq_readiness_policy_workspace"),)


class ReadinessTrigger(TimestampMixin, Base):
    __tablename__ = "readiness_triggers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    external_key: Mapped[str] = mapped_column(String(200), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    service_source_key: Mapped[str | None] = mapped_column(String(500))
    service_node_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="SET NULL"))
    advisory_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    correlation_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="SET NULL"))
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'open'"))
    provenance: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "external_key", name="uq_readiness_trigger_key"),
        Index("ix_readiness_triggers_scope", "tenant_id", "workspace_id", "created_at"),
    )


class ReadinessRecommendation(TimestampMixin, Base):
    __tablename__ = "readiness_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    trigger_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_triggers.id", ondelete="CASCADE"), nullable=False)
    external_key: Mapped[str] = mapped_column(String(200), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'candidate'"))
    service_source_key: Mapped[str] = mapped_column(String(500), nullable=False)
    service_node_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="SET NULL"))
    asset_source_key: Mapped[str | None] = mapped_column(String(500))
    asset_node_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="SET NULL"))
    control_title: Mapped[str] = mapped_column(String(200), nullable=False)
    check_id: Mapped[str] = mapped_column(String(120), nullable=False)
    check_version: Mapped[str] = mapped_column(String(32), nullable=False)
    match_classification: Mapped[str] = mapped_column(String(64), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_recommendations.id", ondelete="SET NULL"))
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    metadata_safe: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("workspace_id", "external_key", name="uq_readiness_recommendation_key"),
        Index("ix_readiness_recommendations_scope", "tenant_id", "workspace_id", "state"),
    )


class ReadinessVerificationRequest(TimestampMixin, Base):
    __tablename__ = "readiness_verification_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    recommendation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_recommendations.id", ondelete="CASCADE"), nullable=False)
    request_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'pending_approval'"))
    check_id: Mapped[str] = mapped_column(String(120), nullable=False)
    check_version: Mapped[str] = mapped_column(String(32), nullable=False)
    runner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("runner_registrations.id", ondelete="SET NULL"))
    connector_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("connector_jobs.id", ondelete="SET NULL"))
    secret_reference: Mapped[str | None] = mapped_column(String(200))
    approved_by: Mapped[str | None] = mapped_column(String(200))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dismissed_by: Mapped[str | None] = mapped_column(String(200))
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("120"))
    expected_data: Mapped[str] = mapped_column(String(500), nullable=False)
    operational_impact: Mapped[str] = mapped_column(String(500), nullable=False)
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    metadata_safe: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("workspace_id", "idempotency_key", name="uq_readiness_request_idempotency"),
        Index("ix_readiness_requests_scope", "tenant_id", "workspace_id", "status"),
    )


class ReadinessResult(TimestampMixin, Base):
    __tablename__ = "readiness_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_verification_requests.id", ondelete="CASCADE"), nullable=False)
    connector_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("connector_jobs.id", ondelete="SET NULL"))
    outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    check_id: Mapped[str] = mapped_column(String(120), nullable=False)
    check_version: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    freshness: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fresh'"))
    replaces_result_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_results.id", ondelete="SET NULL"))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    metadata_safe: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (Index("ix_readiness_results_scope", "tenant_id", "workspace_id", "request_id"),)


class ReadinessDecision(TimestampMixin, Base):
    __tablename__ = "readiness_decisions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_verification_requests.id", ondelete="CASCADE"), nullable=False)
    result_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_results.id", ondelete="SET NULL"))
    outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    rationale: Mapped[str] = mapped_column(String(1000), nullable=False)
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_decisions.id", ondelete="SET NULL"))

    __table_args__ = (Index("ix_readiness_decisions_scope", "tenant_id", "workspace_id", "request_id"),)


class ReadinessEvidenceLink(Base):
    __tablename__ = "readiness_evidence_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_verification_requests.id", ondelete="CASCADE"), nullable=False)
    result_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_results.id", ondelete="SET NULL"))
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("evidence_records.id", ondelete="CASCADE"), nullable=False)
    relationship: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("workspace_id", "request_id", "evidence_id", "relationship", name="uq_readiness_evidence_link"),
    )


class ReadinessAudit(Base):
    __tablename__ = "readiness_audit"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (Index("ix_readiness_audit_scope", "tenant_id", "workspace_id", "at"),)


class ReadinessAction(TimestampMixin, Base):
    __tablename__ = "readiness_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    external_key: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'open'"))
    priority: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'normal'"))
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    why: Mapped[str] = mapped_column(Text, nullable=False)
    what_changed: Mapped[str] = mapped_column(String(500), nullable=False)
    required_work: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence_required: Mapped[str] = mapped_column(String(500), nullable=False)
    known: Mapped[str] = mapped_column(String(500), nullable=False)
    uncertain: Mapped[str] = mapped_column(String(500), nullable=False)
    closure_guidance: Mapped[str] = mapped_column(String(500), nullable=False)
    service_source_key: Mapped[str] = mapped_column(String(500), nullable=False)
    service_node_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="SET NULL"))
    control_title: Mapped[str] = mapped_column(String(200), nullable=False)
    trigger_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_triggers.id", ondelete="SET NULL"))
    recommendation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_recommendations.id", ondelete="SET NULL"))
    request_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_verification_requests.id", ondelete="SET NULL"))
    result_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_results.id", ondelete="SET NULL"))
    decision_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_decisions.id", ondelete="SET NULL"))
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("evidence_records.id", ondelete="SET NULL"))
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="SET NULL"))
    owner_identity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id", ondelete="SET NULL"))
    owner_subject: Mapped[str | None] = mapped_column(String(200))
    reviewer_identity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id", ondelete="SET NULL"))
    reviewer_subject: Mapped[str | None] = mapped_column(String(200))
    assigned_by: Mapped[str | None] = mapped_column(String(200))
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_by: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closure_outcome: Mapped[str | None] = mapped_column(String(64))
    closure_rationale: Mapped[str | None] = mapped_column(String(1000))
    closed_by: Mapped[str | None] = mapped_column(String(200))
    evidence_hash_at_closure: Mapped[str | None] = mapped_column(String(64))
    risk_accepted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_scope: Mapped[str | None] = mapped_column(String(500))
    reopen_reason: Mapped[str | None] = mapped_column(String(500))
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_actions.id", ondelete="SET NULL"))
    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_actions.id", ondelete="SET NULL"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    metadata_safe: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("workspace_id", "external_key", name="uq_readiness_action_key"),
        Index("ix_readiness_actions_scope", "tenant_id", "workspace_id", "status"),
        Index("ix_readiness_actions_owner", "workspace_id", "owner_identity_id"),
        Index("ix_readiness_actions_due", "workspace_id", "due_at"),
    )


class ReadinessActionAssignment(Base):
    __tablename__ = "readiness_action_assignments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False)
    owner_identity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id", ondelete="SET NULL"))
    owner_subject: Mapped[str | None] = mapped_column(String(200))
    assigned_by: Mapped[str] = mapped_column(String(200), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    note: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("''"))

    __table_args__ = (Index("ix_readiness_action_assignments_action", "workspace_id", "action_id", "assigned_at"),)


class ReadinessClosureRequirement(TimestampMixin, Base):
    __tablename__ = "readiness_closure_requirements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False)
    requirement_type: Mapped[str] = mapped_column(String(64), nullable=False)
    requirement_version: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'v1'"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'pending'"))
    mandatory: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("evidence_records.id", ondelete="SET NULL"))
    evidence_hash: Mapped[str | None] = mapped_column(String(64))
    reviewer: Mapped[str | None] = mapped_column(String(200))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    provenance: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("workspace_id", "action_id", "requirement_type", name="uq_readiness_closure_requirement"),
        Index("ix_readiness_closure_requirements_action", "workspace_id", "action_id", "status"),
    )


class ReadinessEvidenceManifest(Base):
    __tablename__ = "readiness_evidence_manifests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'threatsight.manifest.v1'"))
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_json: Mapped[str] = mapped_column(Text, nullable=False)
    previous_manifest_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_evidence_manifests.id", ondelete="SET NULL"))
    generated_by: Mapped[str] = mapped_column(String(200), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("workspace_id", "action_id", "digest", name="uq_readiness_manifest_digest"),
        Index("ix_readiness_manifests_action", "workspace_id", "action_id", "generated_at"),
    )
