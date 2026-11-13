"""M5 AI discovery tables.

Revision ID: 0005_m5
Revises: 0004_m3
Create Date: 2026-08-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_m5"
down_revision: str | None = "0004_m3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "discovery_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("owner", sa.String(200), nullable=False),
        sa.Column("authorized", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("authorization_expires_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("last_scan_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("url", name="uq_discovery_sources_url"),
    )
    op.create_table(
        "discovery_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "source_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("discovery_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("confirm_execution", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("robots_checked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("pages_fetched", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("content_hash", sa.String(64)),
        sa.Column("error", sa.Text()),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_discovery_scans_source", "discovery_scans", ["source_id"])
    op.create_table(
        "discovered_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "source_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("discovery_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("discovery_scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("source_id", "url", name="uq_discovered_assets_source_url"),
    )
    op.create_index("ix_discovered_assets_source", "discovered_assets", ["source_id"])
    op.create_table(
        "discovery_signals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "source_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("discovery_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("discovery_scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("discovered_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("signal_kind", sa.String(64), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("quote", sa.String(2000), nullable=False),
        sa.Column("page_url", sa.String(500), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("review_status", sa.String(32), nullable=False),
        sa.Column("reviewer", sa.String(200)),
        sa.Column("review_comment", sa.Text()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evidence_records.id", ondelete="SET NULL"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "source_id",
            "signal_kind",
            "page_url",
            "content_hash",
            name="uq_discovery_signal_identity",
        ),
    )
    op.create_index("ix_discovery_signals_status", "discovery_signals", ["review_status"])


def downgrade() -> None:
    op.drop_index("ix_discovery_signals_status", table_name="discovery_signals")
    op.drop_table("discovery_signals")
    op.drop_index("ix_discovered_assets_source", table_name="discovered_assets")
    op.drop_table("discovered_assets")
    op.drop_index("ix_discovery_scans_source", table_name="discovery_scans")
    op.drop_table("discovery_scans")
    op.drop_table("discovery_sources")
