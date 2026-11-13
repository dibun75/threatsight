"""Phase 3E response workspace tables. Does not duplicate actions, manifests, signatures, or threat records."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatsight_api.persistence.models import Base, TimestampMixin


class ResponseWorkspace(TimestampMixin, Base):
    __tablename__ = "response_workspaces"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    stable_key: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'assessment'"))
    lifecycle: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'draft'"))
    declaration_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'not_declared'"))
    evidence_assessment: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unreviewed'"))
    reason: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    known_facts: Mapped[str] = mapped_column(String(4000), nullable=False, server_default=text("''"))
    uncertain_facts: Mapped[str] = mapped_column(String(4000), nullable=False, server_default=text("''"))
    operational_impact: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    external_communication_state: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'none_drafted'"))
    regulatory_profile_state: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'not_selected'"))
    owner_identity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id", ondelete="SET NULL"))
    proposed_participants: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    classification: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'operational'"))
    next_review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    activated_by: Mapped[str | None] = mapped_column(String(200))
    activation_rationale: Mapped[str | None] = mapped_column(String(2000))
    declared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    declared_by: Mapped[str | None] = mapped_column(String(200))
    declaration_rationale: Mapped[str | None] = mapped_column(String(2000))
    remaining_uncertainty: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_by: Mapped[str | None] = mapped_column(String(200))
    closure_notes: Mapped[str | None] = mapped_column(String(4000))
    lessons_learned: Mapped[str | None] = mapped_column(String(4000))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    metadata_safe: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("workspace_id", "stable_key", name="uq_response_workspace_stable"),
        UniqueConstraint("workspace_id", "idempotency_key", name="uq_response_workspace_idem"),
        CheckConstraint(
            "mode IN ('assessment','exercise','incident_response')",
            name="ck_response_workspace_mode",
        ),
        CheckConstraint(
            "lifecycle IN ('draft','monitoring','assessing','activated','recovery_review','closed','cancelled')",
            name="ck_response_workspace_lifecycle",
        ),
        CheckConstraint(
            "declaration_state IN ('not_declared','suspected_incident','confirmed_incident','ruled_out')",
            name="ck_response_workspace_declaration",
        ),
        CheckConstraint(
            "evidence_assessment IN ('unreviewed','suspected','supported','conflicting','not_supported','unknown')",
            name="ck_response_workspace_evidence",
        ),
        Index("ix_response_workspaces_ws_life", "workspace_id", "lifecycle"),
        Index("ix_response_workspaces_ws_mode", "workspace_id", "mode"),
    )


class ResponseIntelligenceLink(TimestampMixin, Base):
    __tablename__ = "response_intelligence_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    link_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    label: Mapped[str] = mapped_column(String(300), nullable=False, server_default=text("''"))
    evidence_assessment: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unreviewed'"))
    notes: Mapped[str] = mapped_column(String(1000), nullable=False, server_default=text("''"))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("response_id", "link_type", "target_id", name="uq_response_intel_link"),
        Index("ix_response_intel_links_ws", "workspace_id", "response_id"),
    )


class ResponseServiceLink(TimestampMixin, Base):
    __tablename__ = "response_service_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    service_key: Mapped[str] = mapped_column(String(128), nullable=False)
    service_name: Mapped[str] = mapped_column(String(300), nullable=False)
    involvement: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'potentially_affected'"))
    notes: Mapped[str] = mapped_column(String(1000), nullable=False, server_default=text("''"))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("response_id", "service_key", name="uq_response_service_link"),
        Index("ix_response_service_links_ws", "workspace_id", "response_id"),
    )


class ResponseRoleAssignment(Base):
    __tablename__ = "response_role_assignments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    role_key: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id", ondelete="SET NULL"))
    display_name: Mapped[str] = mapped_column(String(200), nullable=False, server_default=text("''"))
    is_orphan: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    assigned_by: Mapped[str] = mapped_column(String(200), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    unassigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    unassigned_by: Mapped[str | None] = mapped_column(String(200))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    notes: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("''"))

    __table_args__ = (
        Index("ix_response_role_active", "response_id", "role_key", "active"),
        Index("ix_response_role_ws", "workspace_id", "response_id"),
    )


class ResponseActionLink(TimestampMixin, Base):
    __tablename__ = "response_action_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False)
    response_role: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("''"))
    linked_by: Mapped[str] = mapped_column(String(200), nullable=False)
    notes: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("''"))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    __table_args__ = (
        UniqueConstraint("response_id", "action_id", name="uq_response_action_link"),
        Index("ix_response_action_links_ws", "workspace_id", "response_id"),
    )


class ResponseTimelineEntry(Base):
    __tablename__ = "response_timeline_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    linked_objects: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    source_maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    evidence_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unreviewed'"))
    provenance: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("response_timeline_entries.id", ondelete="SET NULL"))
    correction_of_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("response_timeline_entries.id", ondelete="SET NULL"))
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    __table_args__ = (
        Index("ix_response_timeline_ws", "workspace_id", "response_id", "event_time"),
        CheckConstraint(
            "category IN ('intelligence_change','assessment_update','evidence_added','action_update',"
            "'verification_result','decision','role_assignment','declaration_change',"
            "'situation_report','communication_draft','closure_reopen')",
            name="ck_response_timeline_category",
        ),
    )


class ResponseDecision(TimestampMixin, Base):
    __tablename__ = "response_decisions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    decision: Mapped[str] = mapped_column(String(500), nullable=False)
    rationale: Mapped[str] = mapped_column(String(4000), nullable=False)
    decision_maker: Mapped[str] = mapped_column(String(200), nullable=False)
    evidence_considered: Mapped[str] = mapped_column(String(4000), nullable=False, server_default=text("''"))
    alternatives: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    remaining_uncertainty: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timeline_entry_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("response_timeline_entries.id", ondelete="SET NULL"))
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("response_id", "idempotency_key", name="uq_response_decision_idem"),
        Index("ix_response_decisions_ws", "workspace_id", "response_id"),
    )


class ResponseEvidenceRef(TimestampMixin, Base):
    __tablename__ = "response_evidence_refs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    ref_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    ref_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    content_hash: Mapped[str | None] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(300), nullable=False, server_default=text("''"))
    evidence_assessment: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unreviewed'"))
    pinned_by: Mapped[str] = mapped_column(String(200), nullable=False)
    metadata_safe: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("response_id", "ref_kind", "ref_id", name="uq_response_evidence_ref"),
        Index("ix_response_evidence_refs_ws", "workspace_id", "response_id"),
    )


class ResponseSituationReport(TimestampMixin, Base):
    __tablename__ = "response_situation_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'draft'"))
    current_status: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    what_changed: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    business_services: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    known_facts: Mapped[str] = mapped_column(String(4000), nullable=False, server_default=text("''"))
    uncertain_facts: Mapped[str] = mapped_column(String(4000), nullable=False, server_default=text("''"))
    actions_and_owners: Mapped[str] = mapped_column(String(4000), nullable=False, server_default=text("''"))
    decisions_required: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    evidence_freshness: Mapped[str] = mapped_column(String(1000), nullable=False, server_default=text("''"))
    external_communication_state: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("''"))
    regulatory_assessment_state: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("''"))
    next_review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(200))
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finalized_by: Mapped[str | None] = mapped_column(String(200))

    __table_args__ = (
        UniqueConstraint("response_id", "version_number", name="uq_response_sitrep_version"),
        CheckConstraint("status IN ('draft','final')", name="ck_response_sitrep_status"),
        Index("ix_response_sitrep_ws", "workspace_id", "response_id"),
    )


class ResponseCommunicationDraft(TimestampMixin, Base):
    __tablename__ = "response_communication_drafts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    template_key: Mapped[str] = mapped_column(String(64), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    subject: Mapped[str] = mapped_column(String(300), nullable=False, server_default=text("''"))
    body_text: Mapped[str] = mapped_column(String(8000), nullable=False, server_default=text("''"))
    approval_status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'draft'"))
    delivery_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'not_sent'"))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(200))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("response_id", "template_key", "version_number", name="uq_response_comm_version"),
        CheckConstraint(
            "template_key IN ('executive_update','internal_technical_update','service_owner_request',"
            "'customer_stakeholder_holding','regulator_notification_preparation')",
            name="ck_response_comm_template",
        ),
        CheckConstraint("delivery_state = 'not_sent'", name="ck_response_comm_not_sent"),
        Index("ix_response_comm_ws", "workspace_id", "response_id"),
    )


class ResponseJurisdictionProfile(TimestampMixin, Base):
    __tablename__ = "response_jurisdiction_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    profile_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    jurisdiction: Mapped[str] = mapped_column(String(128), nullable=False)
    source_urls: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    summary: Mapped[str] = mapped_column(String(4000), nullable=False)
    uncertainty_notes: Mapped[str] = mapped_column(String(2000), nullable=False, server_default=text("''"))
    default_deadline_hours: Mapped[int | None] = mapped_column(Integer)
    not_legal_advice: Mapped[str] = mapped_column(String(500), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))


class ResponseRegulatoryAssessment(TimestampMixin, Base):
    __tablename__ = "response_regulatory_assessments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    profile_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_jurisdiction_profiles.id", ondelete="RESTRICT"), nullable=False)
    legal_applicability: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'not_determined'"))
    reporting_obligation: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'not_determined'"))
    deadline_hours_confirmed: Mapped[int | None] = mapped_column(Integer)
    deadline_confirmed_by: Mapped[str | None] = mapped_column(String(200))
    deadline_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    liaison_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    liaison_identity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id", ondelete="SET NULL"))
    evidence_notes: Mapped[str] = mapped_column(String(4000), nullable=False, server_default=text("''"))
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("response_id", name="uq_response_regulatory_one"),
        CheckConstraint(
            "legal_applicability IN ('not_determined','possibly_applicable','not_applicable','confirmed_applicable')",
            name="ck_response_reg_applicability",
        ),
        CheckConstraint(
            "reporting_obligation IN ('not_determined','possibly_required','not_required','confirmed_required')",
            name="ck_response_reg_reporting",
        ),
    )


class ResponseSnapshot(TimestampMixin, Base):
    __tablename__ = "response_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'draft'"))
    canonical_json: Mapped[str] = mapped_column(Text, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    generated_by: Mapped[str] = mapped_column(String(200), nullable=False)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finalized_by: Mapped[str | None] = mapped_column(String(200))
    action_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_actions.id", ondelete="SET NULL"))
    manifest_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_evidence_manifests.id", ondelete="SET NULL"))
    signature_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("evidence_signatures.id", ondelete="SET NULL"))
    signing_request_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("evidence_signing_requests.id", ondelete="SET NULL"))
    integrity_disclaimer: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        server_default=text("'Signature proves snapshot integrity only—not incident truth, compliance, or legal validity.'"),
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("response_id", "idempotency_key", name="uq_response_snapshot_idem"),
        CheckConstraint("status IN ('draft','final','signing','signed')", name="ck_response_snapshot_status"),
        Index("ix_response_snapshots_ws", "workspace_id", "response_id"),
    )


class ResponseAuditEvent(Base):
    __tablename__ = "response_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    response_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("response_workspaces.id", ondelete="SET NULL"))
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (Index("ix_response_audit_ws", "workspace_id", "created_at"),)
