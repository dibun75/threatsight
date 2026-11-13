"""Multi-source exploitation intelligence tables and warehouse reference.

Revision ID: 0028_multisource_intelligence
Revises: 0027_verifiable_evidence
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0028_multisource_intelligence"
down_revision = "0027_verifiable_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "intelligence_source_documents",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_key", sa.String(64), nullable=False),
        sa.Column("source_role", sa.String(64), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False),
        sa.Column("canonical_url", sa.String(1000)),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("source_updated_at", sa.DateTime(timezone=True)),
        sa.Column("first_collected_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_collected_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("metadata_safe", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("maturity", sa.String(32), nullable=False, server_default=sa.text("'fixture_tested'")),
        sa.Column("correction_state", sa.String(32), nullable=False, server_default=sa.text("'current'")),
        sa.Column("parser_version", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("source_key", "external_id", name="uq_intel_source_document"),
    )
    op.create_index("ix_intel_source_documents_role", "intelligence_source_documents", ["source_role"])
    op.create_index("ix_intel_source_documents_updated", "intelligence_source_documents", ["source_updated_at"])

    op.create_table(
        "intelligence_assertions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("document_id", UUID(as_uuid=True), sa.ForeignKey("intelligence_source_documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject_key", sa.String(256), nullable=False),
        sa.Column("assertion_type", sa.String(64), nullable=False),
        sa.Column("value", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("effective_at", sa.DateTime(timezone=True)),
        sa.Column("source_role", sa.String(64), nullable=False),
        sa.Column("parser_version", sa.String(64), nullable=False),
        sa.Column("provenance", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("limitations", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_intel_assertions_type", "intelligence_assertions", ["assertion_type"])
    op.create_index("ix_intel_assertions_subject", "intelligence_assertions", ["subject_key"])
    op.create_index("ix_intel_assertions_document", "intelligence_assertions", ["document_id"])

    op.create_table(
        "intelligence_clusters",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("primary_key_type", sa.String(32), nullable=False),
        sa.Column("primary_key_value", sa.String(128), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("exploitation_state", sa.String(64), nullable=False, server_default=sa.text("'unknown'")),
        sa.Column("exploitation_explanation", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("aliases", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("maturity", sa.String(32), nullable=False, server_default=sa.text("'fixture_tested'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("primary_key_type", "primary_key_value", name="uq_intel_cluster_key"),
    )
    op.create_index("ix_intel_clusters_exploit_state", "intelligence_clusters", ["exploitation_state"])

    op.create_table(
        "intelligence_cluster_documents",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", UUID(as_uuid=True), sa.ForeignKey("intelligence_clusters.id", ondelete="CASCADE"), nullable=False),
        sa.Column("document_id", UUID(as_uuid=True), sa.ForeignKey("intelligence_source_documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("cluster_id", "document_id", name="uq_intel_cluster_document"),
    )

    op.create_table(
        "intelligence_change_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", UUID(as_uuid=True), sa.ForeignKey("intelligence_clusters.id", ondelete="CASCADE"), nullable=False),
        sa.Column("change_type", sa.String(64), nullable=False),
        sa.Column("materiality_reason", sa.Text(), nullable=False),
        sa.Column("old_evidence", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("new_evidence", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("source_key", sa.String(64), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("ruleset_version", sa.String(64), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("readiness_triggered", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_index("ix_intel_change_cluster", "intelligence_change_events", ["cluster_id", "detected_at"])

    op.create_table(
        "intelligence_source_health",
        sa.Column("source_key", sa.String(64), primary_key=True),
        sa.Column("source_role", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("kill_switch", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("maturity", sa.String(32), nullable=False, server_default=sa.text("'fixture_tested'")),
        sa.Column("token_required", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(64)),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("etag", sa.String(256)),
        sa.Column("last_known_good_hash", sa.String(64)),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.execute(
        """
        INSERT INTO intelligence_source_health (source_key, source_role, enabled, maturity, token_required)
        VALUES
          ('siemens-productcert', 'vendor_authority', true, 'live_collectable', false),
          ('vulncheck-kev', 'exploitation_observation', false, 'credential_required', true),
          ('the-hacker-news', 'media_discovery', true, 'live_collectable', false)
        ON CONFLICT (source_key) DO NOTHING
        """
    )

    from threatsight_api.multisource.reference import install

    install(op.get_bind())


def downgrade() -> None:
    from threatsight_api.multisource.reference import uninstall

    uninstall(op.get_bind())
    op.drop_table("intelligence_change_events")
    op.drop_table("intelligence_cluster_documents")
    op.drop_table("intelligence_assertions")
    op.drop_table("intelligence_clusters")
    op.drop_table("intelligence_source_documents")
    op.drop_table("intelligence_source_health")
