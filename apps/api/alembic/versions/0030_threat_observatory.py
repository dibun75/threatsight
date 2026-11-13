"""Source-separated public threat observations.

Revision ID: 0030_threat_observatory
Revises: 0029_response_workspace
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0030_threat_observatory"
down_revision = "0029_response_workspace"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "observatory_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("retrieved_at", sa.DateTime(timezone=True)),
        sa.Column("attribution", sa.String(300), nullable=False),
        sa.Column("terms_state", sa.String(64), nullable=False, server_default=sa.text("'attribution_required_no_resale'")),
        sa.Column("content_hash", sa.String(64)),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("annotations", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.CheckConstraint(
            "status IN ('disabled','collecting','succeeded','failed_no_snapshot','failed_using_last_known_good')",
            name="ck_observatory_run_status",
        ),
    )
    op.create_index("ix_observatory_runs_source_current", "observatory_runs", ["source", "is_current"])
    op.create_table(
        "observatory_observations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("observatory_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("indicator_type", sa.String(32), nullable=False),
        sa.Column("indicator", sa.String(300), nullable=False),
        sa.Column("port", sa.Integer()),
        sa.Column("service", sa.String(80)),
        sa.Column("category", sa.String(80), nullable=False),
        sa.Column("country_code", sa.String(2)),
        sa.Column("first_seen", sa.Date()),
        sa.Column("last_seen", sa.Date()),
        sa.Column("detail", sa.String(500), nullable=False, server_default=sa.text("''")),
        sa.Column("count", sa.BigInteger()),
        sa.Column("rank", sa.Integer()),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("reference_url", sa.String(500), nullable=False),
        sa.Column("confidence", sa.String(32), nullable=False, server_default=sa.text("'source_reported'")),
        sa.Column("metadata_safe", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.CheckConstraint("port IS NULL OR (port >= 1 AND port <= 65535)", name="ck_observatory_port"),
    )
    op.create_index("ix_observatory_observations_run_rank", "observatory_observations", ["run_id", "rank"])
    op.create_index("ix_observatory_observations_kind", "observatory_observations", ["source", "kind", "category"])


def downgrade() -> None:
    op.drop_table("observatory_observations")
    op.drop_table("observatory_runs")
