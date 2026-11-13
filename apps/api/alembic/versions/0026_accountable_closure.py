"""Accountable readiness-action closure tables."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0026_accountable_closure"
down_revision = "0025_continuous_readiness"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "readiness_actions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_key", sa.String(200), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("priority", sa.String(32), nullable=False, server_default="normal"),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("why", sa.Text(), nullable=False),
        sa.Column("what_changed", sa.String(500), nullable=False),
        sa.Column("required_work", sa.String(500), nullable=False),
        sa.Column("evidence_required", sa.String(500), nullable=False),
        sa.Column("known", sa.String(500), nullable=False),
        sa.Column("uncertain", sa.String(500), nullable=False),
        sa.Column("closure_guidance", sa.String(500), nullable=False),
        sa.Column("service_source_key", sa.String(500), nullable=False),
        sa.Column("service_node_id", UUID(as_uuid=True), sa.ForeignKey("graph_nodes.id", ondelete="SET NULL")),
        sa.Column("control_title", sa.String(200), nullable=False),
        sa.Column("trigger_id", UUID(as_uuid=True), sa.ForeignKey("readiness_triggers.id", ondelete="SET NULL")),
        sa.Column("recommendation_id", UUID(as_uuid=True), sa.ForeignKey("readiness_recommendations.id", ondelete="SET NULL")),
        sa.Column("request_id", UUID(as_uuid=True), sa.ForeignKey("readiness_verification_requests.id", ondelete="SET NULL")),
        sa.Column("result_id", UUID(as_uuid=True), sa.ForeignKey("readiness_results.id", ondelete="SET NULL")),
        sa.Column("decision_id", UUID(as_uuid=True), sa.ForeignKey("readiness_decisions.id", ondelete="SET NULL")),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_records.id", ondelete="SET NULL")),
        sa.Column("snapshot_id", UUID(as_uuid=True), sa.ForeignKey("graph_snapshots.id", ondelete="SET NULL")),
        sa.Column("owner_identity_id", UUID(as_uuid=True), sa.ForeignKey("identities.id", ondelete="SET NULL")),
        sa.Column("owner_subject", sa.String(200)),
        sa.Column("reviewer_identity_id", UUID(as_uuid=True), sa.ForeignKey("identities.id", ondelete="SET NULL")),
        sa.Column("reviewer_subject", sa.String(200)),
        sa.Column("assigned_by", sa.String(200)),
        sa.Column("assigned_at", sa.DateTime(timezone=True)),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.Column("review_by", sa.DateTime(timezone=True)),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("closure_outcome", sa.String(64)),
        sa.Column("closure_rationale", sa.String(1000)),
        sa.Column("closed_by", sa.String(200)),
        sa.Column("evidence_hash_at_closure", sa.String(64)),
        sa.Column("risk_accepted_until", sa.DateTime(timezone=True)),
        sa.Column("risk_review_at", sa.DateTime(timezone=True)),
        sa.Column("risk_scope", sa.String(500)),
        sa.Column("reopen_reason", sa.String(500)),
        sa.Column("supersedes_id", UUID(as_uuid=True), sa.ForeignKey("readiness_actions.id", ondelete="SET NULL")),
        sa.Column("superseded_by_id", UUID(as_uuid=True), sa.ForeignKey("readiness_actions.id", ondelete="SET NULL")),
        sa.Column("maturity", sa.String(32), nullable=False, server_default="fixture_tested"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("metadata_safe", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "external_key", name="uq_readiness_action_key"),
    )
    op.create_index("ix_readiness_actions_scope", "readiness_actions", ["tenant_id", "workspace_id", "status"])
    op.create_index("ix_readiness_actions_owner", "readiness_actions", ["workspace_id", "owner_identity_id"])
    op.create_index("ix_readiness_actions_due", "readiness_actions", ["workspace_id", "due_at"])
    op.create_table(
        "readiness_action_assignments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_id", UUID(as_uuid=True), sa.ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("owner_identity_id", UUID(as_uuid=True), sa.ForeignKey("identities.id", ondelete="SET NULL")),
        sa.Column("owner_subject", sa.String(200)),
        sa.Column("assigned_by", sa.String(200), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("note", sa.String(500), nullable=False, server_default=""),
    )
    op.create_index("ix_readiness_action_assignments_action", "readiness_action_assignments", ["workspace_id", "action_id", "assigned_at"])
    op.create_table(
        "readiness_closure_requirements",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_id", UUID(as_uuid=True), sa.ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requirement_type", sa.String(64), nullable=False),
        sa.Column("requirement_version", sa.String(32), nullable=False, server_default="v1"),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("mandatory", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_records.id", ondelete="SET NULL")),
        sa.Column("evidence_hash", sa.String(64)),
        sa.Column("reviewer", sa.String(200)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("limitations", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("provenance", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "action_id", "requirement_type", name="uq_readiness_closure_requirement"),
    )
    op.create_index("ix_readiness_closure_requirements_action", "readiness_closure_requirements", ["workspace_id", "action_id", "status"])
    op.create_table(
        "readiness_evidence_manifests",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_id", UUID(as_uuid=True), sa.ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False, server_default="threatsight.manifest.v1"),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("canonical_json", sa.Text(), nullable=False),
        sa.Column("previous_manifest_id", UUID(as_uuid=True), sa.ForeignKey("readiness_evidence_manifests.id", ondelete="SET NULL")),
        sa.Column("generated_by", sa.String(200), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "action_id", "digest", name="uq_readiness_manifest_digest"),
    )
    op.create_index("ix_readiness_manifests_action", "readiness_evidence_manifests", ["workspace_id", "action_id", "generated_at"])
    from threatsight_api.readiness.action_reference import install

    install(op.get_bind())


def downgrade() -> None:
    for table in (
        "readiness_evidence_manifests",
        "readiness_closure_requirements",
        "readiness_action_assignments",
        "readiness_actions",
    ):
        op.drop_table(table)
    op.execute("DELETE FROM readiness_audit WHERE object_type = 'action'")
    op.execute("DELETE FROM identities WHERE issuer = 'synthetic-reference' AND subject LIKE 'ready-owner-%'")
