"""Workspace exposure analysis runs and results.

Revision ID: 0015_exposure_analysis
Revises: 0014_exposure_graph
Create Date: 2026-10-30

Additive only. Downgrade drops these tables and does not change graph or Phase 1 tables.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015_exposure_analysis"
down_revision: str | None = "0014_exposure_graph"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CATEGORY = "category IN ('internet_exposure_candidate','management_plane_candidate','privileged_identity_path','cross_domain_service_path','contradiction_gap')"
_STATE = "state IN ('supported_candidate','unknown','conflicting','unsupported','not_evaluated')"
_STATUS = "status IN ('building','completed','failed','cancelled')"
_MATURITY = "maturity IN ('synthetic','fixture_tested','live_verified')"
_FRESH = "freshness IN ('fresh','stale','untested')"


def _uuid(name: str) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), primary_key=name == "id", nullable=False)


def upgrade() -> None:
    op.create_table(
        "analysis_runs",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        _uuid("snapshot_id"),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("identity", sa.String(64), nullable=False),
        sa.Column("ruleset_version", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("result_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("failure_code", sa.String(64)),
        sa.Column("supersedes_id", postgresql.UUID(as_uuid=True)),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["graph_snapshots.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["supersedes_id"], ["analysis_runs.id"], ondelete="SET NULL"),
        sa.CheckConstraint(_STATUS, name="ck_analysis_run_status"),
    )
    op.create_index("ix_analysis_runs_scope", "analysis_runs", ["tenant_id", "workspace_id", "status"])
    op.create_index("uq_analysis_run_current", "analysis_runs", ["workspace_id"], unique=True, postgresql_where=sa.text("is_current"))
    op.create_index("uq_analysis_run_completed_key", "analysis_runs", ["workspace_id", "idempotency_key"], unique=True, postgresql_where=sa.text("status = 'completed'"))

    op.create_table(
        "analysis_results",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        _uuid("run_id"),
        _uuid("snapshot_id"),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("rule_id", sa.String(80), nullable=False),
        sa.Column("rule_version", sa.String(16), nullable=False),
        sa.Column("service_key", sa.String(500)),
        sa.Column("explanation", sa.String(400), nullable=False),
        sa.Column("evidence_modes", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("maturity", sa.String(32), nullable=False),
        sa.Column("freshness", sa.String(16), nullable=False),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("missing_facts", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("node_keys", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("edge_keys", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["analysis_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["graph_snapshots.id"], ondelete="CASCADE"),
        sa.CheckConstraint(_CATEGORY, name="ck_analysis_result_category"),
        sa.CheckConstraint(_STATE, name="ck_analysis_result_state"),
        sa.CheckConstraint(_MATURITY, name="ck_analysis_result_maturity"),
        sa.CheckConstraint(_FRESH, name="ck_analysis_result_freshness"),
    )
    op.create_index("ix_analysis_results_scope", "analysis_results", ["tenant_id", "workspace_id", "run_id", "category", "state"])


def downgrade() -> None:
    op.drop_index("ix_analysis_results_scope", table_name="analysis_results")
    op.drop_table("analysis_results")
    op.drop_index("uq_analysis_run_completed_key", table_name="analysis_runs")
    op.drop_index("uq_analysis_run_current", table_name="analysis_runs")
    op.drop_index("ix_analysis_runs_scope", table_name="analysis_runs")
    op.drop_table("analysis_runs")
