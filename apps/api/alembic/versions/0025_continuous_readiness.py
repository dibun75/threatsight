"""Threat-triggered continuous readiness reference tables."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0025_continuous_readiness"
down_revision = "0024_reference_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "readiness_policies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("approval_mode", sa.String(64), nullable=False, server_default="manual_approval_required"),
        sa.Column("kill_switch", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("max_recommendations_per_trigger", sa.Integer(), nullable=False, server_default="20"),
        sa.Column("max_executions_per_workspace", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", name="uq_readiness_policy_workspace"),
    )
    op.create_table(
        "readiness_triggers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_key", sa.String(200), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("service_source_key", sa.String(500)),
        sa.Column("service_node_id", UUID(as_uuid=True), sa.ForeignKey("graph_nodes.id", ondelete="SET NULL")),
        sa.Column("advisory_id", UUID(as_uuid=True)),
        sa.Column("correlation_run_id", UUID(as_uuid=True)),
        sa.Column("snapshot_id", UUID(as_uuid=True), sa.ForeignKey("graph_snapshots.id", ondelete="SET NULL")),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False, server_default="fixture_tested"),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("provenance", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "external_key", name="uq_readiness_trigger_key"),
    )
    op.create_index("ix_readiness_triggers_scope", "readiness_triggers", ["tenant_id", "workspace_id", "created_at"])
    op.create_table(
        "readiness_recommendations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("trigger_id", UUID(as_uuid=True), sa.ForeignKey("readiness_triggers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_key", sa.String(200), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="candidate"),
        sa.Column("service_source_key", sa.String(500), nullable=False),
        sa.Column("service_node_id", UUID(as_uuid=True), sa.ForeignKey("graph_nodes.id", ondelete="SET NULL")),
        sa.Column("asset_source_key", sa.String(500)),
        sa.Column("asset_node_id", UUID(as_uuid=True), sa.ForeignKey("graph_nodes.id", ondelete="SET NULL")),
        sa.Column("control_title", sa.String(200), nullable=False),
        sa.Column("check_id", sa.String(120), nullable=False),
        sa.Column("check_version", sa.String(32), nullable=False),
        sa.Column("match_classification", sa.String(64), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("ruleset_version", sa.String(32), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False, server_default="fixture_tested"),
        sa.Column("superseded_by_id", UUID(as_uuid=True), sa.ForeignKey("readiness_recommendations.id", ondelete="SET NULL")),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("metadata_safe", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "external_key", name="uq_readiness_recommendation_key"),
    )
    op.create_index("ix_readiness_recommendations_scope", "readiness_recommendations", ["tenant_id", "workspace_id", "state"])
    op.create_table(
        "readiness_verification_requests",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("recommendation_id", UUID(as_uuid=True), sa.ForeignKey("readiness_recommendations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_type", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending_approval"),
        sa.Column("check_id", sa.String(120), nullable=False),
        sa.Column("check_version", sa.String(32), nullable=False),
        sa.Column("runner_id", UUID(as_uuid=True), sa.ForeignKey("runner_registrations.id", ondelete="SET NULL")),
        sa.Column("connector_job_id", UUID(as_uuid=True), sa.ForeignKey("connector_jobs.id", ondelete="SET NULL")),
        sa.Column("secret_reference", sa.String(200)),
        sa.Column("approved_by", sa.String(200)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("dismissed_by", sa.String(200)),
        sa.Column("dismissed_at", sa.DateTime(timezone=True)),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="120"),
        sa.Column("expected_data", sa.String(500), nullable=False),
        sa.Column("operational_impact", sa.String(500), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False, server_default="fixture_tested"),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("metadata_safe", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "idempotency_key", name="uq_readiness_request_idempotency"),
    )
    op.create_index("ix_readiness_requests_scope", "readiness_verification_requests", ["tenant_id", "workspace_id", "status"])
    op.create_table(
        "readiness_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_id", UUID(as_uuid=True), sa.ForeignKey("readiness_verification_requests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("connector_job_id", UUID(as_uuid=True), sa.ForeignKey("connector_jobs.id", ondelete="SET NULL")),
        sa.Column("outcome", sa.String(64), nullable=False),
        sa.Column("check_id", sa.String(120), nullable=False),
        sa.Column("check_version", sa.String(32), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("limitations", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("maturity", sa.String(32), nullable=False, server_default="fixture_tested"),
        sa.Column("freshness", sa.String(32), nullable=False, server_default="fresh"),
        sa.Column("replaces_result_id", UUID(as_uuid=True), sa.ForeignKey("readiness_results.id", ondelete="SET NULL")),
        sa.Column("collected_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("metadata_safe", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_readiness_results_scope", "readiness_results", ["tenant_id", "workspace_id", "request_id"])
    op.create_table(
        "readiness_decisions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_id", UUID(as_uuid=True), sa.ForeignKey("readiness_verification_requests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("result_id", UUID(as_uuid=True), sa.ForeignKey("readiness_results.id", ondelete="SET NULL")),
        sa.Column("outcome", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("rationale", sa.String(1000), nullable=False),
        sa.Column("supersedes_id", UUID(as_uuid=True), sa.ForeignKey("readiness_decisions.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_readiness_decisions_scope", "readiness_decisions", ["tenant_id", "workspace_id", "request_id"])
    op.create_table(
        "readiness_evidence_links",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_id", UUID(as_uuid=True), sa.ForeignKey("readiness_verification_requests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("result_id", UUID(as_uuid=True), sa.ForeignKey("readiness_results.id", ondelete="SET NULL")),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_records.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "request_id", "evidence_id", "relationship", name="uq_readiness_evidence_link"),
    )
    op.create_table(
        "readiness_audit",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("object_type", sa.String(64), nullable=False),
        sa.Column("object_id", UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("payload", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_readiness_audit_scope", "readiness_audit", ["tenant_id", "workspace_id", "at"])
    from threatsight_api.readiness.reference import install

    install(op.get_bind())


def downgrade() -> None:
    for table in (
        "readiness_audit",
        "readiness_evidence_links",
        "readiness_decisions",
        "readiness_results",
        "readiness_verification_requests",
        "readiness_recommendations",
        "readiness_triggers",
        "readiness_policies",
    ):
        op.drop_table(table)
    op.execute(
        """
        DELETE FROM evidence_records
        WHERE source_reference LIKE 'synthetic-readiness:%'
          AND id NOT IN (SELECT evidence_id FROM findings WHERE evidence_id IS NOT NULL)
        """
    )
