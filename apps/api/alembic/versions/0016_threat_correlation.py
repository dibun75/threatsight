"""Threat correlation runs, matches, reviews, and aliases.

Revision ID: 0016_threat_correlation
Revises: 0015_exposure_analysis
Create Date: 2026-10-31

Additive only. Downgrade drops these tables and does not change graph, analysis, or Phase 1 tables.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016_threat_correlation"
down_revision: str | None = "0015_exposure_analysis"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATE = "state IN ('confirmed_identifier_match','version_supported_candidate','possible_match','unknown','conflicting','not_applicable_by_evidence')"
_REVIEW = "decision IN ('accepted_relevant','not_applicable','needs_more_data','suppressed_until')"
_STATUS = "status IN ('building','completed','failed','cancelled')"
_MATURITY = "maturity IN ('synthetic','fixture_tested','live_verified')"
_FRESH = "freshness IN ('fresh','stale','untested')"


def _uuid(name: str) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), primary_key=name == "id", nullable=False)


def upgrade() -> None:
    op.create_table(
        "correlation_runs",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        _uuid("snapshot_id"),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("identity", sa.String(64), nullable=False),
        sa.Column("ruleset_version", sa.String(32), nullable=False),
        sa.Column("threat_fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("match_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("failure_code", sa.String(64)),
        sa.Column("supersedes_id", postgresql.UUID(as_uuid=True)),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["graph_snapshots.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["supersedes_id"], ["correlation_runs.id"], ondelete="SET NULL"),
        sa.CheckConstraint(_STATUS, name="ck_correlation_run_status"),
    )
    op.create_index("ix_correlation_runs_scope", "correlation_runs", ["tenant_id", "workspace_id", "status"])
    op.create_index("uq_correlation_run_current", "correlation_runs", ["workspace_id"], unique=True, postgresql_where=sa.text("is_current"))
    op.create_index("uq_correlation_run_completed_key", "correlation_runs", ["workspace_id", "idempotency_key"], unique=True, postgresql_where=sa.text("status = 'completed'"))

    op.create_table(
        "correlation_matches",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        _uuid("run_id"),
        _uuid("snapshot_id"),
        sa.Column("match_key", sa.String(64), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(40), nullable=False),
        sa.Column("rule_id", sa.String(80), nullable=False),
        sa.Column("rule_version", sa.String(16), nullable=False),
        sa.Column("cve", sa.String(20), nullable=False),
        sa.Column("asset_key", sa.String(500), nullable=False),
        sa.Column("event_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("cluster_keys", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("sources", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("source_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("services", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("evidence_mode", sa.String(16), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False),
        sa.Column("freshness", sa.String(16), nullable=False),
        sa.Column("identifier_evidence", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("version_evidence", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("provenance", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("geography", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("epss_score", sa.Float()),
        sa.Column("epss_date", sa.String(32)),
        sa.Column("exploitation_status", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("missing_facts", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("explanation", sa.String(400), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["correlation_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["graph_snapshots.id"], ondelete="CASCADE"),
        sa.CheckConstraint(_STATE, name="ck_correlation_match_state"),
        sa.CheckConstraint(_MATURITY, name="ck_correlation_match_maturity"),
        sa.CheckConstraint(_FRESH, name="ck_correlation_match_freshness"),
    )
    op.create_index("ix_correlation_matches_scope", "correlation_matches", ["tenant_id", "workspace_id", "run_id", "state"])

    op.create_table(
        "correlation_reviews",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        sa.Column("match_key", sa.String(64), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(400), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.CheckConstraint(_REVIEW, name="ck_correlation_review_decision"),
    )
    op.create_index("ix_correlation_reviews_scope", "correlation_reviews", ["tenant_id", "workspace_id", "match_key", "created_at"])

    op.create_table(
        "correlation_aliases",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        sa.Column("alias_vendor", sa.String(64), nullable=False),
        sa.Column("alias_product", sa.String(64), nullable=False),
        sa.Column("vendor", sa.String(64), nullable=False),
        sa.Column("product", sa.String(64), nullable=False),
        sa.Column("version", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(400), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("workspace_id", "alias_vendor", "alias_product", name="uq_correlation_alias"),
    )


def downgrade() -> None:
    op.drop_table("correlation_aliases")
    op.drop_index("ix_correlation_reviews_scope", table_name="correlation_reviews")
    op.drop_table("correlation_reviews")
    op.drop_index("ix_correlation_matches_scope", table_name="correlation_matches")
    op.drop_table("correlation_matches")
    op.drop_index("uq_correlation_run_completed_key", table_name="correlation_runs")
    op.drop_index("uq_correlation_run_current", table_name="correlation_runs")
    op.drop_index("ix_correlation_runs_scope", table_name="correlation_runs")
    op.drop_table("correlation_runs")
