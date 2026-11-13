"""Phase 3D multi-source intelligence persistence."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatsight_api.persistence.models import Base


class IntelligenceSourceDocument(Base):
    __tablename__ = "intelligence_source_documents"
    __table_args__ = (
        UniqueConstraint("source_key", "external_id", name="uq_intel_source_document"),
        Index("ix_intel_source_documents_role", "source_role"),
        Index("ix_intel_source_documents_updated", "source_updated_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_key: Mapped[str] = mapped_column(String(64), nullable=False)
    source_role: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False)
    canonical_url: Mapped[str | None] = mapped_column(String(1000))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_safe: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    correction_state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'current'"))
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IntelligenceAssertion(Base):
    __tablename__ = "intelligence_assertions"
    __table_args__ = (
        Index("ix_intel_assertions_type", "assertion_type"),
        Index("ix_intel_assertions_subject", "subject_key"),
        Index("ix_intel_assertions_document", "document_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("intelligence_source_documents.id", ondelete="CASCADE"), nullable=False
    )
    subject_key: Mapped[str] = mapped_column(String(256), nullable=False)
    assertion_type: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    effective_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_role: Mapped[str] = mapped_column(String(64), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IntelligenceCluster(Base):
    __tablename__ = "intelligence_clusters"
    __table_args__ = (
        UniqueConstraint("primary_key_type", "primary_key_value", name="uq_intel_cluster_key"),
        Index("ix_intel_clusters_exploit_state", "exploitation_state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    primary_key_type: Mapped[str] = mapped_column(String(32), nullable=False)
    primary_key_value: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    exploitation_state: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'unknown'"))
    exploitation_explanation: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("''"))
    aliases: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IntelligenceClusterDocument(Base):
    __tablename__ = "intelligence_cluster_documents"
    __table_args__ = (UniqueConstraint("cluster_id", "document_id", name="uq_intel_cluster_document"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("intelligence_clusters.id", ondelete="CASCADE"), nullable=False
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("intelligence_source_documents.id", ondelete="CASCADE"), nullable=False
    )
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IntelligenceChangeEvent(Base):
    __tablename__ = "intelligence_change_events"
    __table_args__ = (Index("ix_intel_change_cluster", "cluster_id", "detected_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("intelligence_clusters.id", ondelete="CASCADE"), nullable=False
    )
    change_type: Mapped[str] = mapped_column(String(64), nullable=False)
    materiality_reason: Mapped[str] = mapped_column(Text, nullable=False)
    old_evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    new_evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    source_key: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    readiness_triggered: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))


class IntelligenceSourceHealth(Base):
    __tablename__ = "intelligence_source_health"

    source_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_role: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    kill_switch: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    token_required: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    consecutive_failures: Mapped[int] = mapped_column(nullable=False, server_default=text("0"))
    etag: Mapped[str | None] = mapped_column(String(256))
    last_known_good_hash: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
