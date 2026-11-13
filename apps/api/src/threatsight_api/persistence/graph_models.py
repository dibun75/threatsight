"""Phase 2 graph tables. Rows are scoped by tenant, workspace, and snapshot."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatsight_api.graph.vocabulary import (
    CONFIDENCE,
    CONFLICT_TYPES,
    EDGE_TYPES,
    EVIDENCE_MODES,
    FRESHNESS,
    LIFECYCLES,
    MATURITIES,
    MEMBER_ROLES,
    NODE_TYPES,
    SNAPSHOT_STATUSES,
    sql_in,
)
from threatsight_api.persistence.base import Base


class GraphSnapshot(Base):
    __tablename__ = "graph_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    materialized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    node_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    edge_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    failure_code: Mapped[str | None] = mapped_column(String(64))
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="SET NULL"))
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint(sql_in("status", SNAPSHOT_STATUSES), name="ck_graph_snapshot_status"),
        Index("ix_graph_snapshots_scope", "tenant_id", "workspace_id", "status"),
        Index("uq_graph_snapshot_current", "workspace_id", unique=True, postgresql_where=text("is_current")),
        Index("uq_graph_snapshot_completed_key", "workspace_id", "idempotency_key", unique=True, postgresql_where=text("status = 'completed'")),
    )


class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="CASCADE"), nullable=False)
    node_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_key: Mapped[str] = mapped_column(String(500), nullable=False)
    vendor_id: Mapped[str] = mapped_column(String(500), nullable=False)
    label: Mapped[str] = mapped_column(String(80), nullable=False)
    maturity: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    connector_key: Mapped[str] = mapped_column(String(64), nullable=False)
    source_contract: Mapped[str] = mapped_column(String(80), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(500), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    materialized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    freshness: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    lifecycle: Mapped[str] = mapped_column(String(32), nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("snapshot_id", "source_key", name="uq_graph_node_source"),
        CheckConstraint(sql_in("node_type", NODE_TYPES), name="ck_graph_node_type"),
        CheckConstraint(sql_in("maturity", MATURITIES), name="ck_graph_node_maturity"),
        CheckConstraint(sql_in("evidence_mode", EVIDENCE_MODES), name="ck_graph_node_evidence"),
        CheckConstraint(sql_in("freshness", FRESHNESS), name="ck_graph_node_freshness"),
        CheckConstraint(sql_in("confidence", CONFIDENCE), name="ck_graph_node_confidence"),
        CheckConstraint(sql_in("lifecycle", LIFECYCLES), name="ck_graph_node_lifecycle"),
        Index("ix_graph_nodes_scope", "tenant_id", "workspace_id", "snapshot_id", "node_type"),
    )


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="CASCADE"), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_key: Mapped[str] = mapped_column(String(500), nullable=False)
    from_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False)
    to_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False)
    maturity: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    connector_key: Mapped[str] = mapped_column(String(64), nullable=False)
    source_contract: Mapped[str] = mapped_column(String(80), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(500), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    materialized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    freshness: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    lifecycle: Mapped[str] = mapped_column(String(32), nullable=False)
    derivation_rule: Mapped[str | None] = mapped_column(String(80))
    derivation_version: Mapped[str | None] = mapped_column(String(16))
    contributing: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))

    __table_args__ = (
        UniqueConstraint("snapshot_id", "source_key", name="uq_graph_edge_source"),
        CheckConstraint(sql_in("edge_type", EDGE_TYPES), name="ck_graph_edge_type"),
        CheckConstraint("evidence_mode <> 'inferred' OR (derivation_rule IS NOT NULL AND derivation_version IS NOT NULL)", name="ck_graph_edge_inferred_rule"),
        CheckConstraint(sql_in("maturity", MATURITIES), name="ck_graph_edge_maturity"),
        CheckConstraint(sql_in("evidence_mode", EVIDENCE_MODES), name="ck_graph_edge_evidence"),
        CheckConstraint(sql_in("freshness", FRESHNESS), name="ck_graph_edge_freshness"),
        CheckConstraint(sql_in("confidence", CONFIDENCE), name="ck_graph_edge_confidence"),
        CheckConstraint(sql_in("lifecycle", LIFECYCLES), name="ck_graph_edge_lifecycle"),
        Index("ix_graph_edges_scope", "tenant_id", "workspace_id", "snapshot_id", "edge_type"),
        Index("ix_graph_edges_from", "from_node_id"),
        Index("ix_graph_edges_to", "to_node_id"),
    )


class GraphObservation(Base):
    __tablename__ = "graph_observations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="CASCADE"), nullable=False)
    subject_key: Mapped[str] = mapped_column(String(500), nullable=False)
    connector_key: Mapped[str] = mapped_column(String(64), nullable=False)
    source_contract: Mapped[str] = mapped_column(String(80), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    maturity: Mapped[str] = mapped_column(String(32), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    materialized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        CheckConstraint(sql_in("evidence_mode", EVIDENCE_MODES), name="ck_graph_observation_evidence"),
        CheckConstraint(sql_in("maturity", MATURITIES), name="ck_graph_observation_maturity"),
        Index("ix_graph_observations_scope", "tenant_id", "workspace_id", "snapshot_id", "subject_key"),
    )


class GraphConflict(Base):
    __tablename__ = "graph_conflicts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="CASCADE"), nullable=False)
    conflict_type: Mapped[str] = mapped_column(String(40), nullable=False)
    subject_key: Mapped[str] = mapped_column(String(500), nullable=False)
    detail_code: Mapped[str] = mapped_column(String(80), nullable=False)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))

    __table_args__ = (
        UniqueConstraint("snapshot_id", "conflict_type", "subject_key", "detail_code", name="uq_graph_conflict"),
        CheckConstraint(sql_in("conflict_type", CONFLICT_TYPES), name="ck_graph_conflict_type"),
        Index("ix_graph_conflicts_scope", "tenant_id", "workspace_id", "snapshot_id"),
    )


class GraphServiceMembership(Base):
    __tablename__ = "graph_service_memberships"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_snapshots.id", ondelete="CASCADE"), nullable=False)
    service_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False)
    member_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    maturity: Mapped[str] = mapped_column(String(32), nullable=False)
    derivation_rule: Mapped[str | None] = mapped_column(String(80))
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    scoped_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("snapshot_id", "service_node_id", "member_node_id", "role", name="uq_graph_membership"),
        CheckConstraint(sql_in("role", MEMBER_ROLES), name="ck_graph_membership_role"),
        CheckConstraint(sql_in("evidence_mode", EVIDENCE_MODES), name="ck_graph_membership_evidence"),
        CheckConstraint(sql_in("maturity", MATURITIES), name="ck_graph_membership_maturity"),
        Index("ix_graph_memberships_scope", "tenant_id", "workspace_id", "snapshot_id"),
    )
