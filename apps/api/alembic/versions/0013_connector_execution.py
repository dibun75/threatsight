"""Connector secrets, outbound runners, instances, and durable jobs.

Revision ID: 0013_connector_execution
Revises: 0012_phase2_trust
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_connector_execution"
down_revision: str | None = "0012_phase2_trust"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(name: str, *, nullable: bool = False) -> sa.Column:
    return sa.Column(
        name,
        postgresql.UUID(as_uuid=True),
        primary_key=name == "id",
        nullable=nullable,
    )


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.create_table(
        "secret_references",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("locator", sa.String(1000), nullable=False),
        sa.Column("version_hint", sa.String(200)),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("workspace_id", "name", name="uq_secret_reference_workspace_name"),
        sa.CheckConstraint("provider IN ('customer_runner','vault','azure_key_vault','aws_secrets_manager','gcp_secret_manager')", name="ck_secret_reference_provider"),
        *_timestamps(),
    )
    op.create_index("ix_secret_references_scope", "secret_references", ["tenant_id", "workspace_id"])

    op.create_table(
        "runner_registrations",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("capabilities", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("workspace_id", "name", name="uq_runner_registration_workspace_name"),
        *_timestamps(),
    )
    op.create_index("ix_runner_registrations_scope", "runner_registrations", ["tenant_id", "workspace_id"])

    op.create_table(
        "runner_credentials",
        _uuid("id"),
        _uuid("runner_id"),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        _uuid("rotated_from_id", nullable=True),
        sa.ForeignKeyConstraint(["runner_id"], ["runner_registrations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rotated_from_id"], ["runner_credentials.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_runner_credentials_runner", "runner_credentials", ["runner_id"])

    op.create_table(
        "connector_instances",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        _uuid("runner_id", nullable=True),
        _uuid("secret_reference_id", nullable=True),
        sa.Column("connector_key", sa.String(64), nullable=False),
        sa.Column("sdk_version", sa.String(32), nullable=False, server_default="v1"),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False, server_default="fixture"),
        sa.Column("maturity", sa.String(32), nullable=False, server_default="unsupported"),
        sa.Column("status", sa.String(32), nullable=False, server_default="disabled"),
        sa.Column("configuration", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("health_state", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("health_detail", sa.String(500)),
        sa.Column("last_health_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["runner_id"], ["runner_registrations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["secret_reference_id"], ["secret_references.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("workspace_id", "name", name="uq_connector_instance_workspace_name"),
        sa.CheckConstraint("mode IN ('fixture','live')", name="ck_connector_instance_mode"),
        sa.CheckConstraint("maturity IN ('unsupported','experimental','fixture_tested','live_verified')", name="ck_connector_instance_maturity"),
        *_timestamps(),
    )
    op.create_index("ix_connector_instances_scope", "connector_instances", ["tenant_id", "workspace_id"])

    op.create_table(
        "connector_jobs",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        _uuid("connector_instance_id"),
        _uuid("runner_id", nullable=True),
        sa.Column("job_type", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("input", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("progress", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("lease_owner", sa.String(200)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(64)),
        sa.Column("last_error_detail", sa.String(500)),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_instance_id"], ["connector_instances.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["runner_id"], ["runner_registrations.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("workspace_id", "idempotency_key", name="uq_connector_job_workspace_idempotency"),
        sa.CheckConstraint("status IN ('queued','leased','running','retry_wait','succeeded','failed','cancelled','dead_letter')", name="ck_connector_job_status"),
        *_timestamps(),
    )
    op.create_index("ix_connector_jobs_claim", "connector_jobs", ["status", "available_at", "priority", "created_at"])
    op.create_index("ix_connector_jobs_scope", "connector_jobs", ["tenant_id", "workspace_id"])

    op.create_table(
        "connector_job_attempts",
        _uuid("id"),
        _uuid("job_id"),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("runner_id", postgresql.UUID(as_uuid=True)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
        sa.Column("error_detail", sa.String(500)),
        sa.Column("result_envelope", postgresql.JSONB()),
        sa.ForeignKeyConstraint(["job_id"], ["connector_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["runner_id"], ["runner_registrations.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("job_id", "attempt_number", name="uq_connector_job_attempt_number"),
    )
    op.create_index("ix_connector_job_attempts_job", "connector_job_attempts", ["job_id"])

    op.create_table(
        "connector_job_audit",
        _uuid("id"),
        _uuid("tenant_id"),
        _uuid("workspace_id"),
        _uuid("job_id"),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["job_id"], ["connector_jobs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_connector_job_audit_scope", "connector_job_audit", ["tenant_id", "workspace_id", "job_id", "at"])


def downgrade() -> None:
    op.drop_table("connector_job_audit")
    op.drop_table("connector_job_attempts")
    op.drop_table("connector_jobs")
    op.drop_table("connector_instances")
    op.drop_table("runner_credentials")
    op.drop_table("runner_registrations")
    op.drop_table("secret_references")
