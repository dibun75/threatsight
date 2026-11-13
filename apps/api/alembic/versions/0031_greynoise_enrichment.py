"""Workspace-scoped on-demand GreyNoise enrichment.

Revision ID: 0031_greynoise_enrichment
Revises: 0030_threat_observatory
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0031_greynoise_enrichment"
down_revision = "0030_threat_observatory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "greynoise_lookups",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id",
            UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ip_address", sa.String(15), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("requested_by", sa.String(200), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("noise", sa.Boolean()),
        sa.Column("riot", sa.Boolean()),
        sa.Column("classification", sa.String(32)),
        sa.Column("name", sa.String(200)),
        sa.Column("provider", sa.String(200)),
        sa.Column("reference_url", sa.String(500)),
        sa.Column("last_seen", sa.Date()),
        sa.Column("message", sa.String(300)),
        sa.Column("error_code", sa.String(64)),
        sa.Column(
            "refresh_requested",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','succeeded','not_found','failed')",
            name="ck_greynoise_lookup_status",
        ),
        sa.CheckConstraint(
            "classification IS NULL OR classification IN ('benign','malicious','unknown')",
            name="ck_greynoise_classification",
        ),
    )
    op.create_index(
        "ix_greynoise_workspace_ip_requested",
        "greynoise_lookups",
        ["workspace_id", "ip_address", "requested_at"],
    )
    op.create_index(
        "ix_greynoise_pending", "greynoise_lookups", ["status", "requested_at"]
    )


def downgrade() -> None:
    op.drop_table("greynoise_lookups")
