"""Runtime settings saved from the Settings page.

Revision ID: 0033_runtime_settings
Revises: 0032_api_tokens_and_alerts
"""

from alembic import op
import sqlalchemy as sa

revision = "0033_runtime_settings"
down_revision = "0032_api_tokens_and_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.String(200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("runtime_settings")
