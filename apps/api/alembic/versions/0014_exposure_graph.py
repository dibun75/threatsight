"""Workspace exposure graph snapshots, nodes, edges, and service membership.

Revision ID: 0014_exposure_graph
Revises: 0013_connector_execution
Create Date: 2026-10-30

Additive only. Downgrade drops these tables and does not change Phase 1 tables.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_exposure_graph"
down_revision: str | None = "0013_connector_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NODE = "node_type IN ('business_service','cloud_subscription','resource_group','cloud_resource','application_service','database_service','load_balancer','identity','group','service_principal','role','role_assignment','network','subnet','public_address','network_interface','device','logical_interface','security_zone','route','security_policy','vpn','site','software_version')"
_EDGE = "edge_type IN ('contains','member_of','assigned_to','attached_to','connected_to','routes_to','in_zone','governed_by','permits_reference','denies_reference','peers_with','depends_on','serves','administered_through','sourced_from')"
_MATURITY = "maturity IN ('synthetic','fixture_tested','live_verified')"
_EVIDENCE = "evidence_mode IN ('observed','configured','inferred','manual')"
_LIFE = "lifecycle IN ('active','stale','missing','superseded','conflicting')"
_FRESH = "freshness IN ('fresh','stale','untested')"
_CONF = "confidence IN ('stated','derived','unknown')"


def _uuid(name: str) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), primary_key=name == "id", nullable=False)


def _scope() -> list[sa.Column]:
    return [
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        _uuid("snapshot_id"),
    ]


def upgrade() -> None:
    op.create_table(
        "graph_snapshots",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("source_fingerprint", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("materialized_at", sa.DateTime(timezone=True)),
        sa.Column("node_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("failure_code", sa.String(64)),
        sa.Column("supersedes_id", postgresql.UUID(as_uuid=True)),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["supersedes_id"], ["graph_snapshots.id"], ondelete="SET NULL"),
        sa.CheckConstraint("status IN ('building','completed','failed','cancelled')", name="ck_graph_snapshot_status"),
    )
    op.create_index("ix_graph_snapshots_scope", "graph_snapshots", ["tenant_id", "workspace_id", "status"])
    op.create_index("uq_graph_snapshot_current", "graph_snapshots", ["workspace_id"], unique=True, postgresql_where=sa.text("is_current"))
    op.create_index("uq_graph_snapshot_completed_key", "graph_snapshots", ["workspace_id", "idempotency_key"], unique=True, postgresql_where=sa.text("status = 'completed'"))

    op.create_table(
        "graph_nodes",
        _uuid("id"),
        *_scope(),
        sa.Column("node_type", sa.String(40), nullable=False),
        sa.Column("source_key", sa.String(500), nullable=False),
        sa.Column("vendor_id", sa.String(500), nullable=False),
        sa.Column("label", sa.String(80), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False),
        sa.Column("evidence_mode", sa.String(32), nullable=False),
        sa.Column("connector_key", sa.String(64), nullable=False),
        sa.Column("source_contract", sa.String(80), nullable=False),
        sa.Column("source_record_id", sa.String(500), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("materialized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("freshness", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("lifecycle", sa.String(32), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["graph_snapshots.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("snapshot_id", "source_key", name="uq_graph_node_source"),
        sa.CheckConstraint(_NODE, name="ck_graph_node_type"),
        sa.CheckConstraint(_MATURITY, name="ck_graph_node_maturity"),
        sa.CheckConstraint(_EVIDENCE, name="ck_graph_node_evidence"),
        sa.CheckConstraint(_FRESH, name="ck_graph_node_freshness"),
        sa.CheckConstraint(_CONF, name="ck_graph_node_confidence"),
        sa.CheckConstraint(_LIFE, name="ck_graph_node_lifecycle"),
    )
    op.create_index("ix_graph_nodes_scope", "graph_nodes", ["tenant_id", "workspace_id", "snapshot_id", "node_type"])

    op.create_table(
        "graph_edges",
        _uuid("id"),
        *_scope(),
        sa.Column("edge_type", sa.String(40), nullable=False),
        sa.Column("source_key", sa.String(500), nullable=False),
        sa.Column("from_node_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("to_node_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False),
        sa.Column("evidence_mode", sa.String(32), nullable=False),
        sa.Column("connector_key", sa.String(64), nullable=False),
        sa.Column("source_contract", sa.String(80), nullable=False),
        sa.Column("source_record_id", sa.String(500), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("materialized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("freshness", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("lifecycle", sa.String(32), nullable=False),
        sa.Column("derivation_rule", sa.String(80)),
        sa.Column("derivation_version", sa.String(16)),
        sa.Column("contributing", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["graph_snapshots.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["from_node_id"], ["graph_nodes.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["to_node_id"], ["graph_nodes.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("snapshot_id", "source_key", name="uq_graph_edge_source"),
        sa.CheckConstraint(_EDGE, name="ck_graph_edge_type"),
        sa.CheckConstraint("evidence_mode <> 'inferred' OR (derivation_rule IS NOT NULL AND derivation_version IS NOT NULL)", name="ck_graph_edge_inferred_rule"),
        sa.CheckConstraint(_MATURITY, name="ck_graph_edge_maturity"),
        sa.CheckConstraint(_EVIDENCE, name="ck_graph_edge_evidence"),
        sa.CheckConstraint(_FRESH, name="ck_graph_edge_freshness"),
        sa.CheckConstraint(_CONF, name="ck_graph_edge_confidence"),
        sa.CheckConstraint(_LIFE, name="ck_graph_edge_lifecycle"),
    )
    op.create_index("ix_graph_edges_scope", "graph_edges", ["tenant_id", "workspace_id", "snapshot_id", "edge_type"])
    op.create_index("ix_graph_edges_from", "graph_edges", ["from_node_id"])
    op.create_index("ix_graph_edges_to", "graph_edges", ["to_node_id"])

    op.create_table(
        "graph_observations",
        _uuid("id"),
        *_scope(),
        sa.Column("subject_key", sa.String(500), nullable=False),
        sa.Column("connector_key", sa.String(64), nullable=False),
        sa.Column("source_contract", sa.String(80), nullable=False),
        sa.Column("source_record_id", sa.String(500), nullable=False),
        sa.Column("evidence_mode", sa.String(32), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("materialized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["graph_snapshots.id"], ondelete="CASCADE"),
        sa.CheckConstraint(_EVIDENCE, name="ck_graph_observation_evidence"),
        sa.CheckConstraint(_MATURITY, name="ck_graph_observation_maturity"),
    )
    op.create_index("ix_graph_observations_scope", "graph_observations", ["tenant_id", "workspace_id", "snapshot_id", "subject_key"])

    op.create_table(
        "graph_conflicts",
        _uuid("id"),
        *_scope(),
        sa.Column("conflict_type", sa.String(40), nullable=False),
        sa.Column("subject_key", sa.String(500), nullable=False),
        sa.Column("detail_code", sa.String(80), nullable=False),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["graph_snapshots.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("snapshot_id", "conflict_type", "subject_key", "detail_code", name="uq_graph_conflict"),
        sa.CheckConstraint("conflict_type IN ('configured_observed','ambiguous_identity','dangling_reference','unsupported','partial_omission','stale_source','duplicate_address','conflicting_assertion')", name="ck_graph_conflict_type"),
    )
    op.create_index("ix_graph_conflicts_scope", "graph_conflicts", ["tenant_id", "workspace_id", "snapshot_id"])

    op.create_table(
        "graph_service_memberships",
        _uuid("id"),
        *_scope(),
        sa.Column("service_node_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("member_node_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("evidence_mode", sa.String(32), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False),
        sa.Column("derivation_rule", sa.String(80)),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("scoped_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["graph_snapshots.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_node_id"], ["graph_nodes.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["member_node_id"], ["graph_nodes.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("snapshot_id", "service_node_id", "member_node_id", "role", name="uq_graph_membership"),
        sa.CheckConstraint("role IN ('entry','dependency','identity','network','administration')", name="ck_graph_membership_role"),
        sa.CheckConstraint(_EVIDENCE, name="ck_graph_membership_evidence"),
        sa.CheckConstraint(_MATURITY, name="ck_graph_membership_maturity"),
    )
    op.create_index("ix_graph_memberships_scope", "graph_service_memberships", ["tenant_id", "workspace_id", "snapshot_id"])


def downgrade() -> None:
    op.drop_table("graph_service_memberships")
    op.drop_table("graph_conflicts")
    op.drop_table("graph_observations")
    op.drop_table("graph_edges")
    op.drop_table("graph_nodes")
    op.drop_table("graph_snapshots")
