"""Phase 0 workspace and normalized threat radar foundation.

Revision ID: 0010_phase0
Revises: 0009_m14
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_phase0"
down_revision: str | None = "0009_m14"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None



def timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.create_table(
        "workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        *timestamps(),
    )
    op.create_table(
        "workspace_memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject", sa.String(200), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("workspace_id", "subject", name="uq_workspace_membership_subject"),
    )
    op.create_index("ix_workspace_memberships_subject", "workspace_memberships", ["subject"])
    op.create_table(
        "organization_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("countries", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("sectors", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("vendors", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("products", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("technologies", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("critical_services", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("minimum_relevance", sa.Integer(), nullable=False, server_default="20"),
        *timestamps(),
    )
    op.create_table(
        "threat_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False, unique=True),
        sa.Column("provider", sa.String(200), nullable=False),
        sa.Column("authority", sa.String(200), nullable=False),
        sa.Column("country", sa.String(2)),
        sa.Column("locator", sa.String(500), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_synced_at", sa.DateTime(timezone=True)),
        sa.Column("last_status", sa.String(32), nullable=False, server_default="never"),
        sa.Column("last_error", sa.String(500)),
        *timestamps(),
    )
    op.create_table(
        "threat_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threat_sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("canonical_url", sa.String(1000), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("source_updated_at", sa.DateTime(timezone=True)),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("countries", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("sectors", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("vendors", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("products", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("technologies", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("cves", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("attributes", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        *timestamps(),
        sa.UniqueConstraint("source_id", "external_id", name="uq_threat_event_source_external"),
    )
    op.create_index("ix_threat_events_published_at", "threat_events", ["published_at"])
    op.create_index("ix_threat_events_content_hash", "threat_events", ["content_hash"])
    op.create_table(
        "vulnerability_signals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cve", sa.String(32), nullable=False, unique=True),
        sa.Column("epss_score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("score_date", sa.DateTime(timezone=True)),
        sa.Column("source", sa.String(64), nullable=False, server_default="first-epss"),
        *timestamps(),
    )
    op.create_table(
        "threat_relevance",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threat_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(32), nullable=False),
        sa.Column("reasons", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("matches", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        *timestamps(),
        sa.UniqueConstraint("workspace_id", "event_id", name="uq_threat_relevance_workspace_event"),
    )
    op.create_index("ix_threat_relevance_workspace_score", "threat_relevance", ["workspace_id", "score"])

    op.execute(
        """
        INSERT INTO workspaces (id, key, name, status)
        VALUES ('00000000-0000-4000-8000-000000000010', 'default', 'Default workspace', 'active')
        """
    )
    op.execute(
        """
        INSERT INTO workspace_memberships (id, workspace_id, subject, role)
        VALUES
          ('00000000-0000-4000-8000-000000000012', '00000000-0000-4000-8000-000000000010', 'operator', 'admin'),
          ('00000000-0000-4000-8000-000000000013', '00000000-0000-4000-8000-000000000010', 'web-proxy', 'operator')
        """
    )
    op.execute(
        """
        INSERT INTO organization_profiles
          (id, workspace_id, countries, sectors, vendors, products, technologies, critical_services, minimum_relevance)
        VALUES
          ('00000000-0000-4000-8000-000000000011', '00000000-0000-4000-8000-000000000010',
           '["NO"]'::jsonb, '["retail"]'::jsonb, '["Cisco", "Juniper", "Meraki", "Microsoft"]'::jsonb,
           '[]'::jsonb, '["firewall", "vpn", "azure"]'::jsonb, '["customer operations"]'::jsonb, 20)
        """
    )
    op.execute(
        """
        INSERT INTO threat_sources (id, key, provider, authority, country, locator)
        VALUES
          ('00000000-0000-4000-8000-000000000020', 'cisa-kev', 'CISA', 'United States CISA', 'US',
           'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
          ('00000000-0000-4000-8000-000000000021', 'nsm-rss', 'NSM', 'Norwegian National Security Authority', 'NO',
           'https://nsm.no/rss/sarbarhetsvarsler-fra-nsm/'),
          ('00000000-0000-4000-8000-000000000022', 'first-epss', 'FIRST', 'FIRST EPSS', NULL,
           'https://api.first.org/data/v1/epss')
        """
    )


def downgrade() -> None:
    op.drop_index("ix_threat_relevance_workspace_score", table_name="threat_relevance")
    op.drop_table("threat_relevance")
    op.drop_table("vulnerability_signals")
    op.drop_index("ix_threat_events_content_hash", table_name="threat_events")
    op.drop_index("ix_threat_events_published_at", table_name="threat_events")
    op.drop_table("threat_events")
    op.drop_table("threat_sources")
    op.drop_table("organization_profiles")
    op.drop_index("ix_workspace_memberships_subject", table_name="workspace_memberships")
    op.drop_table("workspace_memberships")
    op.drop_table("workspaces")
