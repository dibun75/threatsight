"""Global telemetry storage and the synthetic ordering journey."""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0021_telemetry_journey"
down_revision = "0020_local_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "telemetry_snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("dataset", sa.String(64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True)),
        sa.Column("window_end", sa.DateTime(timezone=True)),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_updated_at", sa.DateTime(timezone=True)),
        sa.Column("units", sa.String(64), nullable=False),
        sa.Column("normalization", sa.String(64), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False),
        sa.Column("limitations", JSONB, nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False),
    )
    op.create_table(
        "telemetry_points",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("snapshot_id", UUID(as_uuid=True), sa.ForeignKey("telemetry_snapshots.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("country_code", sa.String(2), nullable=False),
        sa.Column("country_name", sa.String(80), nullable=False),
        sa.Column("value", sa.Float()),
        sa.Column("rank", sa.Integer()),
        sa.Column("note", sa.String(200), nullable=False),
    )
    op.create_table(
        "reference_journeys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("chain_key", sa.String(80), nullable=False),
        sa.Column("service_source_key", sa.String(500), nullable=False),
        sa.Column("match_id", UUID(as_uuid=True)),
        sa.Column("edge_id", UUID(as_uuid=True)),
        sa.Column("consequence", sa.Text(), nullable=False),
        sa.Column("decision_text", sa.Text(), nullable=False),
        sa.Column("control_title", sa.String(200), nullable=False),
        sa.Column("evidence_status", sa.String(32), nullable=False),
        sa.Column("action_title", sa.String(200), nullable=False),
        sa.Column("owner_state", sa.String(32), nullable=False),
        sa.Column("deadline_state", sa.String(32), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False),
        sa.UniqueConstraint("workspace_id", "chain_key", name="uq_reference_journey"),
    )
    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            INSERT INTO landscape_advisories (
                id, source_key, external_id, title, summary, canonical_url, vendor, vendor_advisory_id, cves,
                vendor_severity, vex_status, kev_listed, exploitation_claim, withdrawn, freshness, conflict,
                maturity, parser_version, evidence_hash, products, geography, limitations
            ) VALUES (
                :id, 'nsm-rss', 'reference-nsm-no', 'NSM authority coverage reference',
                'Synthetic marker that the NSM source jurisdiction is Norway. It is not Norwegian attack activity.',
                'https://nsm.no/rss/sarbarhetsvarsler-fra-nsm/', 'NSM', 'reference-nsm-no', '[]'::jsonb,
                'unknown', 'unknown', false, 'no_claim', false, 'fresh', false, 'fixture_tested',
                'landscape-v1', 'reference-nsm-no', '[]'::jsonb,
                '[{"role":"authority_jurisdiction","country":"NO"}]'::jsonb,
                '["authority_jurisdiction_is_not_target","synthetic_reference"]'::jsonb
            )
            ON CONFLICT (source_key, external_id) DO NOTHING
            """
        ),
        {"id": str(uuid.uuid4())},
    )
    from threatsight_api.investigations.reference import install

    install(bind)


def downgrade() -> None:
    op.execute("DELETE FROM analysis_results WHERE rule_id = 'reference-ordering-chain-v1'")
    op.execute("DELETE FROM graph_edges WHERE source_key = 'synthetic.fixture:edge:customer-ordering-widget'")
    op.execute("DELETE FROM landscape_advisories WHERE source_key = 'nsm-rss' AND external_id = 'reference-nsm-no'")
    op.drop_table("reference_journeys")
    op.drop_table("telemetry_points")
    op.drop_table("telemetry_snapshots")
