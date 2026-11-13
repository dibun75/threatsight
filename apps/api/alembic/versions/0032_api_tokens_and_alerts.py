"""Read-only API tokens and alert destinations.

Revision ID: 0032_api_tokens_and_alerts
Revises: 0031_greynoise_enrichment
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0032_api_tokens_and_alerts"
down_revision = "0031_greynoise_enrichment"
branch_labels = None
depends_on = None


def _fk(table: str, column: str = "id") -> sa.ForeignKey:
    return sa.ForeignKey(f"{table}.{column}", ondelete="CASCADE")


def upgrade() -> None:
    now = sa.text("now()")
    op.create_table(
        "api_tokens",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), _fk("tenants"), nullable=False),
        sa.Column("identity_id", UUID(as_uuid=True), _fk("identities"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=now),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_api_tokens_tenant", "api_tokens", ["tenant_id", "created_at"])
    op.create_table(
        "alert_destinations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), _fk("tenants"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), _fk("workspaces"), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("label", sa.String(80), nullable=False),
        sa.Column("url", sa.String(1000)),
        sa.Column("secret", sa.String(200)),
        sa.Column("host", sa.String(253)),
        sa.Column("port", sa.Integer()),
        sa.Column("protocol", sa.String(8), nullable=False, server_default=sa.text("'udp'")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=now),
        sa.CheckConstraint("kind IN ('webhook','slack','teams','syslog')", name="ck_alert_destination_kind"),
    )
    op.create_index("ix_alert_destinations_workspace", "alert_destinations", ["workspace_id"])
    op.create_table(
        "alert_deliveries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), _fk("tenants"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), _fk("workspaces"), nullable=False),
        sa.Column("destination_id", UUID(as_uuid=True), sa.ForeignKey("alert_destinations.id", ondelete="SET NULL")),
        sa.Column("destination_label", sa.String(80), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("subject", sa.String(200)),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("error", sa.String(300)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=now),
    )
    op.create_index("ix_alert_deliveries_workspace", "alert_deliveries", ["workspace_id", "created_at"])


def downgrade() -> None:
    op.drop_table("alert_deliveries")
    op.drop_table("alert_destinations")
    op.drop_table("api_tokens")
