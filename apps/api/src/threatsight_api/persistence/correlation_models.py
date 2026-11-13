"""Phase 2 correlation tables. Reviews do not change threat or graph rows."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatsight_api.correlation.vocabulary import REVIEW_STATES, RUN_STATUSES, STATES, sql_in
from threatsight_api.graph.vocabulary import FRESHNESS, MATURITIES
from threatsight_api.persistence.base import Base


class CorrelationRun(Base):
    __tablename__ = "correlation_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="CASCADE"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    identity: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    threat_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    failure_code: Mapped[str | None] = mapped_column(String(64))
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("correlation_runs.id", ondelete="SET NULL"))
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(sql_in("status", RUN_STATUSES), name="ck_correlation_run_status"),
        Index("ix_correlation_runs_scope", "tenant_id", "workspace_id", "status"),
        Index("uq_correlation_run_current", "workspace_id", unique=True, postgresql_where=text("is_current")),
        Index("uq_correlation_run_completed_key", "workspace_id", "idempotency_key", unique=True, postgresql_where=text("status = 'completed'")),
    )


class CorrelationMatch(Base):
    __tablename__ = "correlation_matches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("correlation_runs.id", ondelete="CASCADE"), nullable=False)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="CASCADE"), nullable=False)
    match_key: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(40), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(80), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(16), nullable=False)
    cve: Mapped[str] = mapped_column(String(20), nullable=False)
    asset_key: Mapped[str] = mapped_column(String(500), nullable=False)
    event_ids: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    cluster_keys: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    sources: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    services: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    evidence_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    maturity: Mapped[str] = mapped_column(String(32), nullable=False)
    freshness: Mapped[str] = mapped_column(String(16), nullable=False)
    identifier_evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    version_evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    provenance: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    geography: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[str | None] = mapped_column(String(32))
    exploitation_status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unknown'"))
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    missing_facts: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    explanation: Mapped[str] = mapped_column(String(400), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(sql_in("state", STATES), name="ck_correlation_match_state"),
        CheckConstraint(sql_in("maturity", MATURITIES), name="ck_correlation_match_maturity"),
        CheckConstraint(sql_in("freshness", FRESHNESS), name="ck_correlation_match_freshness"),
        Index("ix_correlation_matches_scope", "tenant_id", "workspace_id", "run_id", "state"),
    )


class CorrelationReview(Base):
    __tablename__ = "correlation_reviews"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    match_key: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(400), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(sql_in("decision", tuple(item for item in REVIEW_STATES if item != "unreviewed")), name="ck_correlation_review_decision"),
        Index("ix_correlation_reviews_scope", "tenant_id", "workspace_id", "match_key", "created_at"),
    )


class CorrelationAlias(Base):
    __tablename__ = "correlation_aliases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    alias_vendor: Mapped[str] = mapped_column(String(64), nullable=False)
    alias_product: Mapped[str] = mapped_column(String(64), nullable=False)
    vendor: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(400), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("workspace_id", "alias_vendor", "alias_product", name="uq_correlation_alias"),
    )
