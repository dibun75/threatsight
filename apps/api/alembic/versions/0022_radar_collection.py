"""Radar collection runs and the fields needed to publish a snapshot."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0022_radar_collection"
down_revision = "0021_telemetry_journey"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "telemetry_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("window_label", sa.String(16)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.add_column("telemetry_snapshots", sa.Column("window_label", sa.String(16)))
    op.add_column("telemetry_snapshots", sa.Column("confidence", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.add_column("telemetry_snapshots", sa.Column("annotations", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.add_column("telemetry_snapshots", sa.Column("run_id", UUID(as_uuid=True)))
    op.alter_column("telemetry_points", "country_code", existing_type=sa.String(2), nullable=True)
    op.alter_column("telemetry_points", "country_name", existing_type=sa.String(80), nullable=True)
    op.add_column("telemetry_points", sa.Column("target_country_code", sa.String(2)))
    op.add_column("telemetry_points", sa.Column("target_country_name", sa.String(80)))
    op.add_column("telemetry_points", sa.Column("observed_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("telemetry_points", "observed_at")
    op.drop_column("telemetry_points", "target_country_name")
    op.drop_column("telemetry_points", "target_country_code")
    op.alter_column("telemetry_points", "country_name", existing_type=sa.String(80), nullable=False)
    op.alter_column("telemetry_points", "country_code", existing_type=sa.String(2), nullable=False)
    op.drop_column("telemetry_snapshots", "run_id")
    op.drop_column("telemetry_snapshots", "annotations")
    op.drop_column("telemetry_snapshots", "confidence")
    op.drop_column("telemetry_snapshots", "window_label")
    op.drop_table("telemetry_runs")
