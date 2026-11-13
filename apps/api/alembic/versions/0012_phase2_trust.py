"""Phase 2 tenant, identity, OIDC session, and workspace trust foundation.

Revision ID: 0012_phase2_trust
Revises: 0011_phase1
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012_phase2_trust"
down_revision: str | None = "0011_phase1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT_TENANT_ID = "00000000-0000-4000-8000-000000000001"


def timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        *timestamps(),
    )
    op.execute(
        f"""INSERT INTO tenants (id, key, name, status)
            VALUES ('{DEFAULT_TENANT_ID}', 'default', 'Default tenant', 'active')"""
    )

    op.add_column("workspaces", sa.Column("tenant_id", postgresql.UUID(as_uuid=True)))
    op.execute(f"UPDATE workspaces SET tenant_id = '{DEFAULT_TENANT_ID}' WHERE tenant_id IS NULL")
    op.alter_column(
        "workspaces",
        "tenant_id",
        nullable=False,
        server_default=sa.text(f"'{DEFAULT_TENANT_ID}'::uuid"),
    )
    op.create_foreign_key(
        "fk_workspaces_tenant_id", "workspaces", "tenants", ["tenant_id"], ["id"], ondelete="RESTRICT"
    )
    op.create_index("ix_workspaces_tenant", "workspaces", ["tenant_id"])

    op.create_table(
        "identities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("issuer", sa.String(500), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(200)),
        sa.Column("email", sa.String(320)),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        *timestamps(),
        sa.UniqueConstraint("issuer", "subject", name="uq_identity_issuer_subject"),
    )
    op.execute(
        """
        INSERT INTO identities (id, issuer, subject, display_name)
        SELECT md5('legacy:' || subject)::uuid, 'urn:threatsight:legacy', subject, subject
        FROM workspace_memberships
        GROUP BY subject
        """
    )
    op.create_table(
        "tenant_memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("identity_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("identities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("tenant_id", "identity_id", name="uq_tenant_membership_identity"),
    )
    op.create_index("ix_tenant_memberships_identity", "tenant_memberships", ["identity_id"])
    op.execute(
        f"""
        INSERT INTO tenant_memberships (id, tenant_id, identity_id, role)
        SELECT md5('tenant-membership:' || i.id::text)::uuid, '{DEFAULT_TENANT_ID}', i.id,
               CASE WHEN bool_or(wm.role = 'auditor') AND NOT bool_or(wm.role <> 'auditor')
                    THEN 'auditor' ELSE 'operator' END
        FROM identities i
        JOIN workspace_memberships wm ON wm.subject = i.subject
        WHERE i.issuer = 'urn:threatsight:legacy'
        GROUP BY i.id
        """
    )
    op.add_column("workspace_memberships", sa.Column("identity_id", postgresql.UUID(as_uuid=True)))
    op.execute(
        """UPDATE workspace_memberships wm SET identity_id = i.id
           FROM identities i
           WHERE i.issuer = 'urn:threatsight:legacy' AND i.subject = wm.subject"""
    )
    op.create_foreign_key(
        "fk_workspace_memberships_identity_id",
        "workspace_memberships",
        "identities",
        ["identity_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_workspace_memberships_identity", "workspace_memberships", ["identity_id"])
    op.execute(
        """UPDATE workspace_memberships SET role = CASE role
           WHEN 'reviewer' THEN 'operator'
           WHEN 'admin' THEN 'workspace-admin'
           ELSE role END"""
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("identity_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("identities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_auth_sessions_identity", "auth_sessions", ["identity_id"])
    op.create_table(
        "oidc_auth_flows",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("state_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("code_verifier", sa.String(128), nullable=False),
        sa.Column("return_to", sa.String(500), nullable=False, server_default="/"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("oidc_auth_flows")
    op.drop_index("ix_auth_sessions_identity", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.execute(
        """UPDATE workspace_memberships SET role = CASE role
           WHEN 'workspace-admin' THEN 'admin' ELSE role END"""
    )
    op.drop_index("ix_workspace_memberships_identity", table_name="workspace_memberships")
    op.drop_constraint("fk_workspace_memberships_identity_id", "workspace_memberships", type_="foreignkey")
    op.drop_column("workspace_memberships", "identity_id")
    op.drop_index("ix_tenant_memberships_identity", table_name="tenant_memberships")
    op.drop_table("tenant_memberships")
    op.drop_table("identities")
    op.drop_index("ix_workspaces_tenant", table_name="workspaces")
    op.drop_constraint("fk_workspaces_tenant_id", "workspaces", type_="foreignkey")
    op.drop_column("workspaces", "tenant_id")
    op.drop_table("tenants")
