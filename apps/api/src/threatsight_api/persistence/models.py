from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, LargeBinary, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threatsight_api.persistence.base import Base


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AISystemRecord(TimestampMixin, Base):
    __tablename__ = "ai_systems"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    team: Mapped[str | None] = mapped_column(String(200))
    lifecycle: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_classification: Mapped[str | None] = mapped_column(String(64))
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    record_origin: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=text("'manual'"),
        default="manual",
    )

    __table_args__ = (UniqueConstraint("name", "environment", name="uq_ai_systems_name_environment"),)


class AISystemProfile(TimestampMixin, Base):
    __tablename__ = "ai_system_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ai_system_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_systems.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    purpose: Mapped[str | None] = mapped_column(Text)
    data_categories: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    users_subjects: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    capabilities: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    missing: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    labelled_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))


class RequirementRecord(TimestampMixin, Base):
    __tablename__ = "requirements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(500))
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), nullable=False)

    control_links: Mapped[list[RequirementControlLink]] = relationship(back_populates="requirement")


class ControlRecord(TimestampMixin, Base):
    __tablename__ = "controls"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identifier: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    lifecycle: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[int] = mapped_column(nullable=False, default=1)
    severity: Mapped[str | None] = mapped_column(String(32))
    assurance_status: Mapped[str] = mapped_column(String(64), nullable=False)
    assurance_rationale: Mapped[str | None] = mapped_column(Text)
    assurance_set_by: Mapped[str | None] = mapped_column(String(200))
    assurance_set_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latest_verdict: Mapped[str | None] = mapped_column(String(32))

    requirement_links: Mapped[list[RequirementControlLink]] = relationship(back_populates="control")
    evidence_links: Mapped[list[EvidenceControlLink]] = relationship(back_populates="control")
    framework_links: Mapped[list[ControlFrameworkLink]] = relationship(back_populates="control")


class RequirementControlLink(TimestampMixin, Base):
    __tablename__ = "requirement_control_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    requirement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("requirements.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    rationale: Mapped[str | None] = mapped_column(Text)
    provenance: Mapped[str | None] = mapped_column(String(500))

    requirement: Mapped[RequirementRecord] = relationship(back_populates="control_links")
    control: Mapped[ControlRecord] = relationship(back_populates="requirement_links")

    __table_args__ = (
        UniqueConstraint("requirement_id", "control_id", name="uq_requirement_control"),
        Index("ix_rcl_control_id", "control_id"),
    )


class EvidenceRecord(TimestampMixin, Base):
    __tablename__ = "evidence_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(500))
    provenance: Mapped[str | None] = mapped_column(Text)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    document_ref: Mapped[str | None] = mapped_column(String(500))
    envelope: Mapped[dict | None] = mapped_column(JSONB)
    integrity_hash: Mapped[str | None] = mapped_column(String(64))

    control_links: Mapped[list[EvidenceControlLink]] = relationship(back_populates="evidence")
    system_links: Mapped[list[EvidenceSystemLink]] = relationship(back_populates="evidence")


class EvidenceControlLink(Base):
    __tablename__ = "evidence_control_links"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_records.id", ondelete="CASCADE"),
        primary_key=True,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("controls.id", ondelete="CASCADE"),
        primary_key=True,
    )

    evidence: Mapped[EvidenceRecord] = relationship(back_populates="control_links")
    control: Mapped[ControlRecord] = relationship(back_populates="evidence_links")


class EvidenceSystemLink(Base):
    __tablename__ = "evidence_system_links"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_records.id", ondelete="CASCADE"),
        primary_key=True,
    )
    ai_system_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_systems.id", ondelete="CASCADE"),
        primary_key=True,
    )

    evidence: Mapped[EvidenceRecord] = relationship(back_populates="system_links")


class FrameworkReference(TimestampMixin, Base):
    __tablename__ = "framework_references"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework_key: Mapped[str] = mapped_column(String(64), nullable=False)
    reference_code: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    locator: Mapped[str | None] = mapped_column(String(500))
    statement: Mapped[str | None] = mapped_column(Text)
    source_kind: Mapped[str | None] = mapped_column(String(32))
    catalog_version: Mapped[str | None] = mapped_column(String(32))
    informational_only: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    __table_args__ = (
        UniqueConstraint("framework_key", "reference_code", name="uq_framework_reference"),
    )


class ControlFrameworkLink(TimestampMixin, Base):
    __tablename__ = "control_framework_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    framework_reference_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("framework_references.id", ondelete="CASCADE"),
        nullable=False,
    )
    note: Mapped[str | None] = mapped_column(Text)

    control: Mapped[ControlRecord] = relationship(back_populates="framework_links")
    framework_reference: Mapped[FrameworkReference] = relationship()

    __table_args__ = (
        UniqueConstraint("control_id", "framework_reference_id", name="uq_control_framework"),
    )


class ReviewRecord(Base):
    __tablename__ = "reviews"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    reviewer: Mapped[str] = mapped_column(String(200), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (Index("ix_reviews_entity", "entity_type", "entity_id"),)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (Index("ix_audit_entity", "entity_type", "entity_id"),)


class SourceDocument(TimestampMixin, Base):
    __tablename__ = "source_documents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    uploaded_by: Mapped[str] = mapped_column(String(200), nullable=False)

    versions: Mapped[list[DocumentVersion]] = relationship(back_populates="document")
    candidates: Mapped[list[ExtractionCandidate]] = relationship(back_populates="document")


class DocumentVersion(TimestampMixin, Base):
    __tablename__ = "document_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("source_documents.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    original_filename: Mapped[str] = mapped_column(String(300), nullable=False)
    media_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    extracted_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    locations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    page_count: Mapped[int | None] = mapped_column(Integer)
    extraction_status: Mapped[str] = mapped_column(String(32), nullable=False)
    extraction_provider: Mapped[str | None] = mapped_column(String(64))
    extraction_model: Mapped[str | None] = mapped_column(String(128))
    extracted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extraction_warnings: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    extraction_error: Mapped[str | None] = mapped_column(Text)
    uploaded_by: Mapped[str] = mapped_column(String(200), nullable=False)

    document: Mapped[SourceDocument] = relationship(back_populates="versions")
    candidates: Mapped[list[ExtractionCandidate]] = relationship(back_populates="version")

    __table_args__ = (
        UniqueConstraint("document_id", "version_number", name="uq_document_version_number"),
        UniqueConstraint("document_id", "content_hash", name="uq_document_content_hash"),
        Index("ix_document_versions_document_id", "document_id"),
    )


class ExtractionCandidate(TimestampMixin, Base):
    __tablename__ = "extraction_candidates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("source_documents.id", ondelete="CASCADE"),
        nullable=False,
    )
    document_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("document_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    candidate_type: Mapped[str] = mapped_column(String(32), nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    page: Mapped[int | None] = mapped_column(Integer)
    section: Mapped[str | None] = mapped_column(String(300))
    start_char: Mapped[int | None] = mapped_column(Integer)
    end_char: Mapped[int | None] = mapped_column(Integer)
    quote: Mapped[str] = mapped_column(Text, nullable=False)
    extraction_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    extraction_model: Mapped[str] = mapped_column(String(128), nullable=False)
    extracted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reviewer: Mapped[str | None] = mapped_column(String(200))
    review_comment: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    authoritative_requirement_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("requirements.id", ondelete="SET NULL"),
    )
    authoritative_control_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("controls.id", ondelete="SET NULL"),
    )
    authoritative_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_records.id", ondelete="SET NULL"),
    )

    document: Mapped[SourceDocument] = relationship(back_populates="candidates")
    version: Mapped[DocumentVersion] = relationship(back_populates="candidates")
    mappings: Mapped[list[CandidateControlMapping]] = relationship(back_populates="candidate")

    __table_args__ = (
        Index("ix_candidates_document_id", "document_id"),
        Index("ix_candidates_version_id", "document_version_id"),
    )


class CandidateControlMapping(TimestampMixin, Base):
    __tablename__ = "candidate_control_mappings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("extraction_candidates.id", ondelete="CASCADE"),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    control_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("controls.id", ondelete="SET NULL"),
    )
    requirement_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("requirements.id", ondelete="SET NULL"),
    )
    mapping_link_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("requirement_control_links.id", ondelete="SET NULL"),
    )
    rationale: Mapped[str | None] = mapped_column(Text)
    reviewer: Mapped[str] = mapped_column(String(200), nullable=False)
    provenance: Mapped[str] = mapped_column(String(500), nullable=False)

    candidate: Mapped[ExtractionCandidate] = relationship(back_populates="mappings")


class AssuranceTargetRecord(TimestampMixin, Base):
    __tablename__ = "assurance_targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ai_system_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_systems.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    adapter: Mapped[str] = mapped_column(String(32), nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    authorization_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AssuranceRunRecord(Base):
    __tablename__ = "assurance_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    ai_system_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assurance_targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    scenario_key: Mapped[str] = mapped_column(String(32), nullable=False)
    configuration: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    observation: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    narration: Mapped[str | None] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_records.id", ondelete="SET NULL"),
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    parent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assurance_runs.id", ondelete="SET NULL"),
    )
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_assurance_runs_control", "control_id"),)


class FindingRecord(TimestampMixin, Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ai_system_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assurance_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_records.id", ondelete="SET NULL"),
    )
    resolved_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assurance_runs.id", ondelete="SET NULL"),
    )
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (Index("ix_findings_control", "control_id"),)


class RemediationRecord(Base):
    __tablename__ = "remediations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class DiscoverySource(TimestampMixin, Base):
    __tablename__ = "discovery_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    authorization_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    __table_args__ = (UniqueConstraint("url", name="uq_discovery_sources_url"),)


class DiscoveryScan(Base):
    __tablename__ = "discovery_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_sources.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    confirm_execution: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    robots_checked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    pages_fetched: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    content_hash: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_discovery_scans_source", "source_id"),)


class DiscoveredAsset(TimestampMixin, Base):
    __tablename__ = "discovered_assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_sources.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("source_id", "url", name="uq_discovered_assets_source_url"),
        Index("ix_discovered_assets_source", "source_id"),
    )


class DiscoverySignal(TimestampMixin, Base):
    __tablename__ = "discovery_signals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_sources.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovered_assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    signal_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    quote: Mapped[str] = mapped_column(String(2000), nullable=False)
    page_url: Mapped[str] = mapped_column(String(500), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), nullable=False)
    reviewer: Mapped[str | None] = mapped_column(String(200))
    review_comment: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_records.id", ondelete="SET NULL"),
    )

    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "signal_kind",
            "page_url",
            "content_hash",
            name="uq_discovery_signal_identity",
        ),
        Index("ix_discovery_signals_status", "review_status"),
    )


class IntelThreat(TimestampMixin, Base):
    __tablename__ = "intel_threats"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(32), nullable=False)
    informational_only: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))


class IntelTechnique(TimestampMixin, Base):
    __tablename__ = "intel_techniques"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    threat_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("intel_threats.id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    locator: Mapped[str] = mapped_column(String(500), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(32), nullable=False)
    framework_key: Mapped[str | None] = mapped_column(String(64))
    reference_code: Mapped[str | None] = mapped_column(String(64))
    affected_capability: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'unknown'"))
    informational_only: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    __table_args__ = (Index("ix_intel_techniques_threat", "threat_id"),)


class IntelAdvisory(TimestampMixin, Base):
    __tablename__ = "intel_advisories"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    locator: Mapped[str] = mapped_column(String(500), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(32), nullable=False)
    ingested_by: Mapped[str] = mapped_column(String(200), nullable=False)
    informational_only: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))


class IntelAdvisoryTechnique(Base):
    __tablename__ = "intel_advisory_techniques"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("intel_advisories.id", ondelete="CASCADE"),
        primary_key=True,
    )
    technique_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("intel_techniques.id", ondelete="CASCADE"),
        primary_key=True,
    )


class IntelTechniqueControl(TimestampMixin, Base):
    __tablename__ = "intel_technique_controls"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    technique_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("intel_techniques.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    note: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("technique_id", "control_id", name="uq_intel_technique_control"),
        Index("ix_intel_technique_controls_control", "control_id"),
    )


class IntelTechniqueTest(TimestampMixin, Base):
    __tablename__ = "intel_technique_tests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    technique_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("intel_techniques.id", ondelete="CASCADE"),
        nullable=False,
    )
    scenario_key: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        UniqueConstraint("technique_id", "scenario_key", name="uq_intel_technique_test"),
    )


class AgentEvent(TimestampMixin, Base):
    __tablename__ = "agent_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ai_system_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_systems.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(200))
    session_id: Mapped[str | None] = mapped_column(String(200))
    user_context: Mapped[str | None] = mapped_column(String(500))
    tool_name: Mapped[str | None] = mapped_column(String(200))
    arguments: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    authorization_context: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    result_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(128))
    labelled_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    __table_args__ = (
        Index("ix_agent_events_system", "ai_system_id"),
        Index("ix_agent_events_occurred", "occurred_at"),
        Index("ix_agent_events_correlation", "correlation_id"),
    )


class IntelligenceRun(TimestampMixin, Base):
    __tablename__ = "intelligence_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    task: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    output: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    confidence: Mapped[float | None] = mapped_column(Float)
    uncertainty: Mapped[str | None] = mapped_column(Text)
    legal_compliance_claim: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    llm_available: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    llm_authored: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    __table_args__ = (Index("ix_intelligence_runs_source", "source_type", "source_id"),)

class Workspace(TimestampMixin, Base):
    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        default=lambda: uuid.UUID("00000000-0000-4000-8000-000000000001"),
        server_default=text("'00000000-0000-4000-8000-000000000001'::uuid"),
    )
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'active'"))
    classification: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unspecified'"))


class WorkspaceMembership(TimestampMixin, Base):
    __tablename__ = "workspace_memberships"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    identity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id", ondelete="CASCADE")
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("workspace_id", "subject", name="uq_workspace_membership_subject"),
        Index("ix_workspace_memberships_subject", "subject"),
        Index("ix_workspace_memberships_identity", "identity_id"),
    )


class Tenant(TimestampMixin, Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'active'"))


class Identity(TimestampMixin, Base):
    __tablename__ = "identities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(200))
    email: Mapped[str | None] = mapped_column(String(320))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'active'"))

    __table_args__ = (UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),)


class TenantMembership(TimestampMixin, Base):
    __tablename__ = "tenant_memberships"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    identity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "identity_id", name="uq_tenant_membership_identity"),
        Index("ix_tenant_memberships_identity", "identity_id"),
    )


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    identity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_auth_sessions_identity", "identity_id"),)


class OIDCAuthFlow(Base):
    __tablename__ = "oidc_auth_flows"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    code_verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    return_to: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("'/'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LocalCredential(Base):
    __tablename__ = "local_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(500), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class LocalAuthToken(Base):
    __tablename__ = "local_auth_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    issuer_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("identities.id", ondelete="SET NULL"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class LocalAuthThrottle(Base):
    __tablename__ = "local_auth_throttles"

    subject_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class OrganizationProfile(TimestampMixin, Base):
    __tablename__ = "organization_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    countries: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    sectors: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    vendors: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    products: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    technologies: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    critical_services: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    minimum_relevance: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("20"))


class ThreatSource(TimestampMixin, Base):
    __tablename__ = "threat_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    provider: Mapped[str] = mapped_column(String(200), nullable=False)
    authority: Mapped[str] = mapped_column(String(200), nullable=False)
    country: Mapped[str | None] = mapped_column(String(2))
    locator: Mapped[str] = mapped_column(String(500), nullable=False)
    source_format: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'json'"))
    sync_mode: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'automatic'"))
    polling_minutes: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("60"))
    jurisdiction: Mapped[str | None] = mapped_column(String(32))
    license_url: Mapped[str | None] = mapped_column(String(500))
    storage_policy: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'metadata_excerpt'"))
    attribution: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("'Source attribution required'"))
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'phase0-v1'"))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'never'"))
    last_error: Mapped[str | None] = mapped_column(String(500))
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    auth_requirement: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'none'"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unspecified'"))
    terms_note: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("''"))
    rate_limit_note: Mapped[str] = mapped_column(String(200), nullable=False, server_default=text("''"))
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))


class ThreatEvent(TimestampMixin, Base):
    __tablename__ = "threat_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_sources.id", ondelete="RESTRICT"), nullable=False
    )
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    canonical_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("1.0"))
    countries: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    authority_jurisdictions: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    target_countries: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    victim_countries: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    infrastructure_countries: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    prevalence_countries: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    sectors: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    vendors: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    products: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    technologies: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    cves: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    exploitation_status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unknown'"))
    source_payload_hash: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("''"))
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'phase0-v1'"))
    provenance: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_threat_event_source_external"),
        Index("ix_threat_events_published_at", "published_at"),
        Index("ix_threat_events_content_hash", "content_hash"),
    )


class VulnerabilitySignal(TimestampMixin, Base):
    __tablename__ = "vulnerability_signals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    epss_score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    score_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'first-epss'"))


class ThreatRelevance(TimestampMixin, Base):
    __tablename__ = "threat_relevance"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_events.id", ondelete="CASCADE"), nullable=False
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[str] = mapped_column(String(32), nullable=False)
    reasons: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    matches: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("workspace_id", "event_id", name="uq_threat_relevance_workspace_event"),
        Index("ix_threat_relevance_workspace_score", "workspace_id", "score"),
    )


class ThreatCluster(TimestampMixin, Base):
    __tablename__ = "threat_clusters"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    factors: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    algorithm_version: Mapped[str] = mapped_column(String(64), nullable=False)


class ThreatClusterMembership(TimestampMixin, Base):
    __tablename__ = "threat_cluster_memberships"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_clusters.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_events.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False)
    factors: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))

    __table_args__ = (
        UniqueConstraint("cluster_id", "event_id", name="uq_threat_cluster_membership"),
        Index("ix_threat_cluster_memberships_event", "event_id"),
    )


class RadarSavedView(TimestampMixin, Base):
    __tablename__ = "radar_saved_views"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    filters: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="uq_radar_saved_view_workspace_name"),
        Index("ix_radar_saved_views_workspace", "workspace_id"),
    )


class RadarTriage(TimestampMixin, Base):
    __tablename__ = "radar_triage"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    subject_type: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[str] = mapped_column(String(32), nullable=False)
    owner: Mapped[str | None] = mapped_column(String(200))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("workspace_id", "subject_type", "subject_id", name="uq_radar_triage_subject"),
        Index("ix_radar_triage_workspace_status", "workspace_id", "status"),
        CheckConstraint("subject_type IN ('event', 'cluster')", name="ck_radar_triage_subject_type"),
    )


class BusinessService(TimestampMixin, Base):
    __tablename__ = "business_services"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    criticality: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unknown'"))

    __table_args__ = (
        UniqueConstraint("workspace_id", "key", name="uq_business_service_workspace_key"),
        Index("ix_business_services_workspace", "workspace_id"),
    )


class WorkspaceResourceBinding(TimestampMixin, Base):
    __tablename__ = "workspace_resource_bindings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    label: Mapped[str] = mapped_column(String(300), nullable=False)
    bound_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("workspace_id", "resource_type", "resource_id", name="uq_workspace_resource_binding"),
        Index("ix_workspace_resource_bindings_workspace", "workspace_id", "resource_type"),
        CheckConstraint(
            "resource_type IN ('control', 'evidence', 'system')",
            name="ck_workspace_resource_binding_type",
        ),
    )


class RadarReadinessLink(TimestampMixin, Base):
    __tablename__ = "radar_readiness_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    subject_type: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    provenance: Mapped[str] = mapped_column(String(500), nullable=False)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    actor: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "workspace_id", "subject_type", "subject_id", "target_type", "target_id",
            name="uq_radar_readiness_link",
        ),
        Index("ix_radar_readiness_links_subject", "workspace_id", "subject_type", "subject_id"),
        CheckConstraint("subject_type IN ('event', 'cluster')", name="ck_radar_link_subject_type"),
        CheckConstraint(
            "target_type IN ('control', 'evidence', 'system', 'business_service')",
            name="ck_radar_link_target_type",
        ),
    )


class RadarWorkflowAudit(Base):
    __tablename__ = "radar_workflow_audit"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (Index("ix_radar_workflow_audit_workspace_at", "workspace_id", "at"),)


class SecretReference(TimestampMixin, Base):
    __tablename__ = "secret_references"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    locator: Mapped[str] = mapped_column(String(1000), nullable=False)
    version_hint: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'active'"))

    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="uq_secret_reference_workspace_name"),
        Index("ix_secret_references_scope", "tenant_id", "workspace_id"),
    )


class RunnerRegistration(TimestampMixin, Base):
    __tablename__ = "runner_registrations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'active'"))
    capabilities: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="uq_runner_registration_workspace_name"),
        Index("ix_runner_registrations_scope", "tenant_id", "workspace_id"),
    )


class RunnerCredential(Base):
    __tablename__ = "runner_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    runner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("runner_registrations.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rotated_from_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("runner_credentials.id", ondelete="SET NULL"))

    __table_args__ = (Index("ix_runner_credentials_runner", "runner_id"),)


class ConnectorInstance(TimestampMixin, Base):
    __tablename__ = "connector_instances"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    runner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("runner_registrations.id", ondelete="SET NULL"))
    secret_reference_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("secret_references.id", ondelete="RESTRICT"))
    connector_key: Mapped[str] = mapped_column(String(64), nullable=False)
    sdk_version: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'v1'"))
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'fixture'"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unsupported'"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'disabled'"))
    configuration: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    health_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unknown'"))
    health_detail: Mapped[str | None] = mapped_column(String(500))
    last_health_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="uq_connector_instance_workspace_name"),
        Index("ix_connector_instances_scope", "tenant_id", "workspace_id"),
    )


class ConnectorJob(TimestampMixin, Base):
    __tablename__ = "connector_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    connector_instance_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("connector_instances.id", ondelete="CASCADE"), nullable=False)
    runner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("runner_registrations.id", ondelete="SET NULL"))
    job_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'queued'"))
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("100"))
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    input: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    progress: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("5"))
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    last_error_detail: Mapped[str | None] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("workspace_id", "idempotency_key", name="uq_connector_job_workspace_idempotency"),
        Index("ix_connector_jobs_claim", "status", "available_at", "priority", "created_at"),
        Index("ix_connector_jobs_scope", "tenant_id", "workspace_id"),
    )


class ConnectorJobAttempt(Base):
    __tablename__ = "connector_job_attempts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("connector_jobs.id", ondelete="CASCADE"), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    runner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("runner_registrations.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_detail: Mapped[str | None] = mapped_column(String(500))
    result_envelope: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("job_id", "attempt_number", name="uq_connector_job_attempt_number"),
        Index("ix_connector_job_attempts_job", "job_id"),
    )


class ConnectorJobAudit(Base):
    __tablename__ = "connector_job_audit"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("connector_jobs.id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (Index("ix_connector_job_audit_scope", "tenant_id", "workspace_id", "job_id", "at"),)


from threatsight_api.persistence.graph_models import (  # noqa: E402,F401
    GraphConflict,
    GraphEdge,
    GraphNode,
    GraphObservation,
    GraphServiceMembership,
    GraphSnapshot,
)
from threatsight_api.persistence.analysis_models import (  # noqa: E402,F401
    AnalysisResult,
    AnalysisRun,
)
from threatsight_api.persistence.correlation_models import (  # noqa: E402,F401
    CorrelationAlias,
    CorrelationMatch,
    CorrelationReview,
    CorrelationRun,
)
from threatsight_api.persistence.landscape_models import (  # noqa: E402,F401
    LandscapeAdvisory,
    LandscapeCatalog,
)
from threatsight_api.persistence.readiness_models import (  # noqa: E402,F401
    ReadinessAction,
    ReadinessActionAssignment,
    ReadinessAudit,
    ReadinessClosureRequirement,
    ReadinessDecision,
    ReadinessEvidenceLink,
    ReadinessEvidenceManifest,
    ReadinessPolicy,
    ReadinessRecommendation,
    ReadinessResult,
    ReadinessTrigger,
    ReadinessVerificationRequest,
)
from threatsight_api.persistence.signing_models import (  # noqa: E402,F401
    EvidenceSignature,
    EvidenceSigningKey,
    EvidenceSigningPolicy,
    EvidenceSigningRequest,
)
from threatsight_api.persistence.multisource_models import (  # noqa: E402,F401
    IntelligenceAssertion,
    IntelligenceChangeEvent,
    IntelligenceCluster,
    IntelligenceClusterDocument,
    IntelligenceSourceDocument,
    IntelligenceSourceHealth,
)
from threatsight_api.persistence.response_models import (  # noqa: E402,F401
    ResponseActionLink,
    ResponseAuditEvent,
    ResponseCommunicationDraft,
    ResponseDecision,
    ResponseEvidenceRef,
    ResponseIntelligenceLink,
    ResponseJurisdictionProfile,
    ResponseRegulatoryAssessment,
    ResponseRoleAssignment,
    ResponseServiceLink,
    ResponseSituationReport,
    ResponseSnapshot,
    ResponseTimelineEntry,
    ResponseWorkspace,
)
