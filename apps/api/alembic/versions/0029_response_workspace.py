"""Response workspace and crisis coordination.

Revision ID: 0029_response_workspace
Revises: 0028_multisource_intelligence
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0029_response_workspace"
down_revision = "0028_multisource_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "response_workspaces",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stable_key", sa.String(128), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False, server_default=sa.text("'assessment'")),
        sa.Column("lifecycle", sa.String(32), nullable=False, server_default=sa.text("'draft'")),
        sa.Column("declaration_state", sa.String(32), nullable=False, server_default=sa.text("'not_declared'")),
        sa.Column("evidence_assessment", sa.String(32), nullable=False, server_default=sa.text("'unreviewed'")),
        sa.Column("reason", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("known_facts", sa.String(4000), nullable=False, server_default=sa.text("''")),
        sa.Column("uncertain_facts", sa.String(4000), nullable=False, server_default=sa.text("''")),
        sa.Column("operational_impact", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("external_communication_state", sa.String(64), nullable=False, server_default=sa.text("'none_drafted'")),
        sa.Column("regulatory_profile_state", sa.String(64), nullable=False, server_default=sa.text("'not_selected'")),
        sa.Column("owner_identity_id", UUID(as_uuid=True), sa.ForeignKey("identities.id", ondelete="SET NULL")),
        sa.Column("proposed_participants", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("classification", sa.String(64), nullable=False, server_default=sa.text("'operational'")),
        sa.Column("next_review_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("activated_by", sa.String(200)),
        sa.Column("activation_rationale", sa.String(2000)),
        sa.Column("declared_at", sa.DateTime(timezone=True)),
        sa.Column("declared_by", sa.String(200)),
        sa.Column("declaration_rationale", sa.String(2000)),
        sa.Column("remaining_uncertainty", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("closed_by", sa.String(200)),
        sa.Column("closure_notes", sa.String(4000)),
        sa.Column("lessons_learned", sa.String(4000)),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("metadata_safe", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "stable_key", name="uq_response_workspace_stable"),
        sa.UniqueConstraint("workspace_id", "idempotency_key", name="uq_response_workspace_idem"),
        sa.CheckConstraint("mode IN ('assessment','exercise','incident_response')", name="ck_response_workspace_mode"),
        sa.CheckConstraint(
            "lifecycle IN ('draft','monitoring','assessing','activated','recovery_review','closed','cancelled')",
            name="ck_response_workspace_lifecycle",
        ),
        sa.CheckConstraint(
            "declaration_state IN ('not_declared','suspected_incident','confirmed_incident','ruled_out')",
            name="ck_response_workspace_declaration",
        ),
        sa.CheckConstraint(
            "evidence_assessment IN ('unreviewed','suspected','supported','conflicting','not_supported','unknown')",
            name="ck_response_workspace_evidence",
        ),
    )
    op.create_index("ix_response_workspaces_ws_life", "response_workspaces", ["workspace_id", "lifecycle"])
    op.create_index("ix_response_workspaces_ws_mode", "response_workspaces", ["workspace_id", "mode"])

    op.create_table(
        "response_jurisdiction_profiles",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("profile_key", sa.String(128), nullable=False, unique=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("jurisdiction", sa.String(128), nullable=False),
        sa.Column("source_urls", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.String(4000), nullable=False),
        sa.Column("uncertainty_notes", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("default_deadline_hours", sa.Integer()),
        sa.Column("not_legal_advice", sa.String(500), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "response_intelligence_links",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("link_type", sa.String(64), nullable=False),
        sa.Column("target_id", UUID(as_uuid=True), nullable=False),
        sa.Column("label", sa.String(300), nullable=False, server_default=sa.text("''")),
        sa.Column("evidence_assessment", sa.String(32), nullable=False, server_default=sa.text("'unreviewed'")),
        sa.Column("notes", sa.String(1000), nullable=False, server_default=sa.text("''")),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("response_id", "link_type", "target_id", name="uq_response_intel_link"),
    )
    op.create_index("ix_response_intel_links_ws", "response_intelligence_links", ["workspace_id", "response_id"])

    op.create_table(
        "response_service_links",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_key", sa.String(128), nullable=False),
        sa.Column("service_name", sa.String(300), nullable=False),
        sa.Column("involvement", sa.String(64), nullable=False, server_default=sa.text("'potentially_affected'")),
        sa.Column("notes", sa.String(1000), nullable=False, server_default=sa.text("''")),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("response_id", "service_key", name="uq_response_service_link"),
    )
    op.create_index("ix_response_service_links_ws", "response_service_links", ["workspace_id", "response_id"])

    op.create_table(
        "response_role_assignments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role_key", sa.String(64), nullable=False),
        sa.Column("identity_id", UUID(as_uuid=True), sa.ForeignKey("identities.id", ondelete="SET NULL")),
        sa.Column("display_name", sa.String(200), nullable=False, server_default=sa.text("''")),
        sa.Column("is_orphan", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("assigned_by", sa.String(200), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("unassigned_at", sa.DateTime(timezone=True)),
        sa.Column("unassigned_by", sa.String(200)),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("notes", sa.String(500), nullable=False, server_default=sa.text("''")),
    )
    op.create_index("ix_response_role_active", "response_role_assignments", ["response_id", "role_key", "active"])
    op.create_index("ix_response_role_ws", "response_role_assignments", ["workspace_id", "response_id"])

    op.create_table(
        "response_action_links",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_id", UUID(as_uuid=True), sa.ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_role", sa.String(64), nullable=False, server_default=sa.text("''")),
        sa.Column("linked_by", sa.String(200), nullable=False),
        sa.Column("notes", sa.String(500), nullable=False, server_default=sa.text("''")),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("response_id", "action_id", name="uq_response_action_link"),
    )
    op.create_index("ix_response_action_links_ws", "response_action_links", ["workspace_id", "response_id"])

    op.create_table(
        "response_timeline_entries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("summary", sa.String(1000), nullable=False),
        sa.Column("linked_objects", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("source_maturity", sa.String(32), nullable=False, server_default=sa.text("'fixture_tested'")),
        sa.Column("evidence_state", sa.String(32), nullable=False, server_default=sa.text("'unreviewed'")),
        sa.Column("provenance", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("supersedes_id", UUID(as_uuid=True), sa.ForeignKey("response_timeline_entries.id", ondelete="SET NULL")),
        sa.Column("correction_of_id", UUID(as_uuid=True), sa.ForeignKey("response_timeline_entries.id", ondelete="SET NULL")),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.CheckConstraint(
            "category IN ('intelligence_change','assessment_update','evidence_added','action_update',"
            "'verification_result','decision','role_assignment','declaration_change',"
            "'situation_report','communication_draft','closure_reopen')",
            name="ck_response_timeline_category",
        ),
    )
    op.create_index("ix_response_timeline_ws", "response_timeline_entries", ["workspace_id", "response_id", "event_time"])

    op.create_table(
        "response_decisions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("decision", sa.String(500), nullable=False),
        sa.Column("rationale", sa.String(4000), nullable=False),
        sa.Column("decision_maker", sa.String(200), nullable=False),
        sa.Column("evidence_considered", sa.String(4000), nullable=False, server_default=sa.text("''")),
        sa.Column("alternatives", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("remaining_uncertainty", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("effective_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("review_at", sa.DateTime(timezone=True)),
        sa.Column("timeline_entry_id", UUID(as_uuid=True), sa.ForeignKey("response_timeline_entries.id", ondelete="SET NULL")),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("response_id", "idempotency_key", name="uq_response_decision_idem"),
    )
    op.create_index("ix_response_decisions_ws", "response_decisions", ["workspace_id", "response_id"])

    op.create_table(
        "response_evidence_refs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ref_kind", sa.String(64), nullable=False),
        sa.Column("ref_id", UUID(as_uuid=True), nullable=False),
        sa.Column("content_hash", sa.String(64)),
        sa.Column("label", sa.String(300), nullable=False, server_default=sa.text("''")),
        sa.Column("evidence_assessment", sa.String(32), nullable=False, server_default=sa.text("'unreviewed'")),
        sa.Column("pinned_by", sa.String(200), nullable=False),
        sa.Column("metadata_safe", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("response_id", "ref_kind", "ref_id", name="uq_response_evidence_ref"),
    )
    op.create_index("ix_response_evidence_refs_ws", "response_evidence_refs", ["workspace_id", "response_id"])

    op.create_table(
        "response_situation_reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'draft'")),
        sa.Column("current_status", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("what_changed", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("business_services", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("known_facts", sa.String(4000), nullable=False, server_default=sa.text("''")),
        sa.Column("uncertain_facts", sa.String(4000), nullable=False, server_default=sa.text("''")),
        sa.Column("actions_and_owners", sa.String(4000), nullable=False, server_default=sa.text("''")),
        sa.Column("decisions_required", sa.String(2000), nullable=False, server_default=sa.text("''")),
        sa.Column("evidence_freshness", sa.String(1000), nullable=False, server_default=sa.text("''")),
        sa.Column("external_communication_state", sa.String(500), nullable=False, server_default=sa.text("''")),
        sa.Column("regulatory_assessment_state", sa.String(500), nullable=False, server_default=sa.text("''")),
        sa.Column("next_review_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("reviewed_by", sa.String(200)),
        sa.Column("finalized_at", sa.DateTime(timezone=True)),
        sa.Column("finalized_by", sa.String(200)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("response_id", "version_number", name="uq_response_sitrep_version"),
        sa.CheckConstraint("status IN ('draft','final')", name="ck_response_sitrep_status"),
    )
    op.create_index("ix_response_sitrep_ws", "response_situation_reports", ["workspace_id", "response_id"])

    op.create_table(
        "response_communication_drafts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("template_key", sa.String(64), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("subject", sa.String(300), nullable=False, server_default=sa.text("''")),
        sa.Column("body_text", sa.String(8000), nullable=False, server_default=sa.text("''")),
        sa.Column("approval_status", sa.String(32), nullable=False, server_default=sa.text("'draft'")),
        sa.Column("delivery_state", sa.String(32), nullable=False, server_default=sa.text("'not_sent'")),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("approved_by", sa.String(200)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("response_id", "template_key", "version_number", name="uq_response_comm_version"),
        sa.CheckConstraint(
            "template_key IN ('executive_update','internal_technical_update','service_owner_request',"
            "'customer_stakeholder_holding','regulator_notification_preparation')",
            name="ck_response_comm_template",
        ),
        sa.CheckConstraint("delivery_state = 'not_sent'", name="ck_response_comm_not_sent"),
    )
    op.create_index("ix_response_comm_ws", "response_communication_drafts", ["workspace_id", "response_id"])

    op.create_table(
        "response_regulatory_assessments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("profile_id", UUID(as_uuid=True), sa.ForeignKey("response_jurisdiction_profiles.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("legal_applicability", sa.String(32), nullable=False, server_default=sa.text("'not_determined'")),
        sa.Column("reporting_obligation", sa.String(32), nullable=False, server_default=sa.text("'not_determined'")),
        sa.Column("deadline_hours_confirmed", sa.Integer()),
        sa.Column("deadline_confirmed_by", sa.String(200)),
        sa.Column("deadline_confirmed_at", sa.DateTime(timezone=True)),
        sa.Column("liaison_confirmed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("liaison_identity_id", UUID(as_uuid=True), sa.ForeignKey("identities.id", ondelete="SET NULL")),
        sa.Column("evidence_notes", sa.String(4000), nullable=False, server_default=sa.text("''")),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("updated_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("response_id", name="uq_response_regulatory_one"),
        sa.CheckConstraint(
            "legal_applicability IN ('not_determined','possibly_applicable','not_applicable','confirmed_applicable')",
            name="ck_response_reg_applicability",
        ),
        sa.CheckConstraint(
            "reporting_obligation IN ('not_determined','possibly_required','not_required','confirmed_required')",
            name="ck_response_reg_reporting",
        ),
    )

    op.create_table(
        "response_snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'draft'")),
        sa.Column("canonical_json", sa.Text(), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("generated_by", sa.String(200), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True)),
        sa.Column("finalized_by", sa.String(200)),
        sa.Column("action_id", UUID(as_uuid=True), sa.ForeignKey("readiness_actions.id", ondelete="SET NULL")),
        sa.Column("manifest_id", UUID(as_uuid=True), sa.ForeignKey("readiness_evidence_manifests.id", ondelete="SET NULL")),
        sa.Column("signature_id", UUID(as_uuid=True), sa.ForeignKey("evidence_signatures.id", ondelete="SET NULL")),
        sa.Column("signing_request_id", UUID(as_uuid=True), sa.ForeignKey("evidence_signing_requests.id", ondelete="SET NULL")),
        sa.Column(
            "integrity_disclaimer",
            sa.String(500),
            nullable=False,
            server_default=sa.text(
                "'Signature proves snapshot integrity only—not incident truth, compliance, or legal validity.'"
            ),
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("response_id", "idempotency_key", name="uq_response_snapshot_idem"),
        sa.CheckConstraint("status IN ('draft','final','signing','signed')", name="ck_response_snapshot_status"),
    )
    op.create_index("ix_response_snapshots_ws", "response_snapshots", ["workspace_id", "response_id"])

    op.create_table(
        "response_audit_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("response_id", UUID(as_uuid=True), sa.ForeignKey("response_workspaces.id", ondelete="SET NULL")),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("detail", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_response_audit_ws", "response_audit_events", ["workspace_id", "created_at"])

    # Seed informational NIS2/Norway profile (not legal advice).
    op.execute(
        sa.text(
            """
            INSERT INTO response_jurisdiction_profiles (
              id, profile_key, title, jurisdiction, source_urls, reviewed_at, summary,
              uncertainty_notes, default_deadline_hours, not_legal_advice, active
            ) VALUES (
              gen_random_uuid(),
              'nis2_norway_informational_v1',
              'NIS2-oriented evidence preparation (Norway informational)',
              'Norway / EU NIS2 context',
              '[{"label":"EUR-Lex NIS2","url":"https://eur-lex.europa.eu/eli/dir/2022/2555/oj"},
                {"label":"EC NIS2 overview","url":"https://digital-strategy.ec.europa.eu/en/policies/nis2-directive"},
                {"label":"Lovdata","url":"https://lovdata.no/"},
                {"label":"NSM","url":"https://nsm.no/"}]'::jsonb,
              TIMESTAMPTZ '2026-11-04T00:00:00Z',
              'Informational profile to organize evidence for NIS2-oriented preparation. '
              'EU directive text does not automatically bind a Norwegian entity without national implementation confirmation. '
              'Operator must confirm jurisdiction, applicability, and any deadlines.',
              'Norwegian transposition status and sectoral scope can change. Display uncertainty rather than inferring EU rules apply directly.',
              NULL,
              'Not legal advice. Jurisdiction profiles organize evidence only; they do not determine legal applicability or regulatory obligations.',
              true
            )
            """
        )
    )

    from threatsight_api.response.reference import install

    install(op.get_bind())


def downgrade() -> None:
    # Remove only Phase 3E structures and reference records.
    op.execute(sa.text("DELETE FROM response_audit_events"))
    op.execute(sa.text("DELETE FROM response_snapshots"))
    op.execute(sa.text("DELETE FROM response_regulatory_assessments"))
    op.execute(sa.text("DELETE FROM response_communication_drafts"))
    op.execute(sa.text("DELETE FROM response_situation_reports"))
    op.execute(sa.text("DELETE FROM response_evidence_refs"))
    op.execute(sa.text("DELETE FROM response_decisions"))
    op.execute(sa.text("DELETE FROM response_timeline_entries"))
    op.execute(sa.text("DELETE FROM response_action_links"))
    op.execute(sa.text("DELETE FROM response_role_assignments"))
    op.execute(sa.text("DELETE FROM response_service_links"))
    op.execute(sa.text("DELETE FROM response_intelligence_links"))
    op.execute(sa.text("DELETE FROM response_workspaces"))
    op.execute(
        sa.text(
            "DELETE FROM readiness_actions WHERE external_key LIKE 'resp-ex-%' OR external_key LIKE 'response-snapshot-%'"
        )
    )
    op.execute(sa.text("DELETE FROM response_jurisdiction_profiles"))
    op.drop_table("response_audit_events")
    op.drop_table("response_snapshots")
    op.drop_table("response_regulatory_assessments")
    op.drop_table("response_communication_drafts")
    op.drop_table("response_situation_reports")
    op.drop_table("response_evidence_refs")
    op.drop_table("response_decisions")
    op.drop_table("response_timeline_entries")
    op.drop_table("response_action_links")
    op.drop_table("response_role_assignments")
    op.drop_table("response_service_links")
    op.drop_table("response_intelligence_links")
    op.drop_table("response_jurisdiction_profiles")
    op.drop_table("response_workspaces")
