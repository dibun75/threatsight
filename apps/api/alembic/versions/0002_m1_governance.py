"""M1 control and governance tables.

Revision ID: 0002_m1
Revises: 0001_m0
Create Date: 2026-08-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_m1"
down_revision: str | None = "0001_m0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_systems",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("owner", sa.String(200), nullable=False),
        sa.Column("team", sa.String(200)),
        sa.Column("lifecycle", sa.String(32), nullable=False),
        sa.Column("risk_classification", sa.String(64)),
        sa.Column("environment", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("name", "environment", name="uq_ai_systems_name_environment"),
    )
    op.create_table(
        "requirements",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_reference", sa.String(500)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "controls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("identifier", sa.String(32), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("owner", sa.String(200), nullable=False),
        sa.Column("lifecycle", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("severity", sa.String(32)),
        sa.Column("assurance_status", sa.String(64), nullable=False),
        sa.Column("assurance_rationale", sa.Text()),
        sa.Column("assurance_set_by", sa.String(200)),
        sa.Column("assurance_set_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("identifier", name="uq_controls_identifier"),
    )
    op.create_table(
        "requirement_control_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("requirement_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("requirements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("controls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rationale", sa.Text()),
        sa.Column("provenance", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("requirement_id", "control_id", name="uq_requirement_control"),
    )
    op.create_index("ix_rcl_control_id", "requirement_control_links", ["control_id"])
    op.create_table(
        "evidence_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("evidence_type", sa.String(32), nullable=False),
        sa.Column("source_reference", sa.String(500)),
        sa.Column("provenance", sa.Text()),
        sa.Column("collected_at", sa.DateTime(timezone=True)),
        sa.Column("owner", sa.String(200), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("document_ref", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "evidence_control_links",
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("evidence_records.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("controls.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_table(
        "evidence_system_links",
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("evidence_records.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("ai_system_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ai_systems.id", ondelete="CASCADE"), primary_key=True),
    )
    op.create_table(
        "framework_references",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("framework_key", sa.String(64), nullable=False),
        sa.Column("reference_code", sa.String(64), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("locator", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("framework_key", "reference_code", name="uq_framework_reference"),
    )
    op.create_table(
        "control_framework_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("controls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("framework_reference_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("framework_references.id", ondelete="CASCADE"), nullable=False),
        sa.Column("note", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("control_id", "framework_reference_id", name="uq_control_framework"),
    )
    op.create_table(
        "reviews",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reviewer", sa.String(200), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("comment", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_reviews_entity", "reviews", ["entity_type", "entity_id"])
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("payload", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
    )
    op.create_index("ix_audit_entity", "audit_events", ["entity_type", "entity_id"])

    framework = sa.table(
        "framework_references",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("framework_key", sa.String),
        sa.column("reference_code", sa.String),
        sa.column("title", sa.String),
        sa.column("locator", sa.String),
    )
    op.bulk_insert(
        framework,
        [
            {
                "id": "a1000000-0000-4000-8000-000000000001",
                "framework_key": "nist_ai_rmf",
                "reference_code": "MAP-1.1",
                "title": "Map AI systems and intended uses",
                "locator": None,
            },
            {
                "id": "a1000000-0000-4000-8000-000000000002",
                "framework_key": "eu_ai_act",
                "reference_code": "Art-9",
                "title": "Risk management system (informational mapping)",
                "locator": None,
            },
            {
                "id": "a1000000-0000-4000-8000-000000000003",
                "framework_key": "gdpr",
                "reference_code": "Art-32",
                "title": "Security of processing (informational mapping)",
                "locator": None,
            },
            {
                "id": "a1000000-0000-4000-8000-000000000004",
                "framework_key": "iso_42001",
                "reference_code": "6.1",
                "title": "Actions to address risks and opportunities",
                "locator": None,
            },
            {
                "id": "a1000000-0000-4000-8000-000000000005",
                "framework_key": "owasp_genai",
                "reference_code": "LLM01",
                "title": "Prompt injection (informational mapping)",
                "locator": None,
            },
            {
                "id": "a1000000-0000-4000-8000-000000000006",
                "framework_key": "mitre_atlas",
                "reference_code": "AML.T0048",
                "title": "External tool invocation (informational mapping)",
                "locator": None,
            },
        ],
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("reviews")
    op.drop_table("control_framework_links")
    op.drop_table("framework_references")
    op.drop_table("evidence_system_links")
    op.drop_table("evidence_control_links")
    op.drop_table("evidence_records")
    op.drop_table("requirement_control_links")
    op.drop_table("controls")
    op.drop_table("requirements")
    op.drop_table("ai_systems")
