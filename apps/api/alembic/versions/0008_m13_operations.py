"""M13 AI security operations tables and technique capability.

Revision ID: 0008_m13
Revises: 0007_m7
Create Date: 2026-08-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_m13"
down_revision: str | None = "0007_m7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "intel_techniques",
        sa.Column("affected_capability", sa.String(64), nullable=False, server_default="unknown"),
    )
    op.create_table(
        "ai_system_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "ai_system_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("purpose", sa.Text()),
        sa.Column("data_categories", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("users_subjects", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("capabilities", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("missing", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("labelled_synthetic", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("ai_system_id", name="uq_ai_system_profiles_system"),
    )
    op.create_table(
        "agent_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "ai_system_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("agent_id", sa.String(200)),
        sa.Column("session_id", sa.String(200)),
        sa.Column("user_context", sa.String(500)),
        sa.Column("tool_name", sa.String(200)),
        sa.Column("arguments", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("authorization_context", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("result_metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_id", sa.String(128)),
        sa.Column("labelled_synthetic", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_agent_events_system", "agent_events", ["ai_system_id"])
    op.create_index("ix_agent_events_occurred", "agent_events", ["occurred_at"])
    op.create_index("ix_agent_events_correlation", "agent_events", ["correlation_id"])
    op.create_table(
        "intelligence_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("task", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(64), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True)),
        sa.Column("prompt_version", sa.String(64), nullable=False),
        sa.Column("output", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("confidence", sa.Float()),
        sa.Column("uncertainty", sa.Text()),
        sa.Column("legal_compliance_claim", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("llm_available", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("llm_authored", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_intelligence_runs_source", "intelligence_runs", ["source_type", "source_id"])


def downgrade() -> None:
    op.drop_index("ix_intelligence_runs_source", table_name="intelligence_runs")
    op.drop_table("intelligence_runs")
    op.drop_index("ix_agent_events_correlation", table_name="agent_events")
    op.drop_index("ix_agent_events_occurred", table_name="agent_events")
    op.drop_index("ix_agent_events_system", table_name="agent_events")
    op.drop_table("agent_events")
    op.drop_table("ai_system_profiles")
    op.drop_column("intel_techniques", "affected_capability")
