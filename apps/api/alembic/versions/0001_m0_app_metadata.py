"""M0 app metadata table.

Revision ID: 0001_m0
Revises:
Create Date: 2026-08-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_m0"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "app_metadata",
        sa.Column("key", sa.Text(), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
    )
    op.execute("INSERT INTO app_metadata (key, value) VALUES ('milestone', 'M0')")
    op.execute("INSERT INTO app_metadata (key, value) VALUES ('schema_family', 'foundation')")


def downgrade() -> None:
    op.drop_table("app_metadata")
