"""Durable public-intelligence collection runs.

Revision ID: 0019_intelligence_runs
Revises: 0018_threat_landscape
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0019_intelligence_runs"
down_revision = "0018_threat_landscape"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "landscape_schedules",
        sa.Column("source_key", sa.String(64), sa.ForeignKey("threat_sources.key", ondelete="CASCADE"), primary_key=True),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("freshness_hours", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("kill_switch", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("lease_owner", sa.String(64)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("cursor", sa.Text()),
        sa.Column("etag", sa.String(200)),
        sa.Column("last_modified", sa.String(200)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error_code", sa.String(64)),
    )
    op.create_table(
        "landscape_collection_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("cursor_after", sa.Text()),
        sa.Column("etag", sa.String(200)),
        sa.Column("records_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_inserted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_withdrawn", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_rejected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(64)),
        sa.Column("response_sha256", sa.String(64), nullable=False, server_default=""),
        sa.Column("parser_version", sa.String(64), nullable=False),
    )
    op.create_index("ix_landscape_collection_runs_source", "landscape_collection_runs", ["source_key", "started_at"])
    op.create_table(
        "epss_observations",
        sa.Column("cve", sa.String(20), nullable=False),
        sa.Column("score_date", sa.Date(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("cve", "score_date", name="pk_epss_observations"),
    )
    op.execute(
        """
        INSERT INTO landscape_schedules (source_key, interval_minutes, freshness_hours, enabled)
        VALUES
          ('first-epss', 1440, 36, true),
          ('nvd-cve', 180, 12, true),
          ('aws-bulletins', 240, 24, true),
          ('fortinet-psirt', 240, 24, true),
          ('paloalto-advisory', 240, 24, true)
        ON CONFLICT (source_key) DO NOTHING
        """
    )
    op.execute(
        """
        UPDATE threat_sources
           SET terms_note = 'CSAF directory is an HTML application shell. The current-month CVRF document exceeds the 4MB collection bound, so it stays fixture-tested.'
         WHERE key = 'msrc-csaf'
        """
    )


def downgrade() -> None:
    op.drop_table("epss_observations")
    op.drop_index("ix_landscape_collection_runs_source", table_name="landscape_collection_runs")
    op.drop_table("landscape_collection_runs")
    op.drop_table("landscape_schedules")
