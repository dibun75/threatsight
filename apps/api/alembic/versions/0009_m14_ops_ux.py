"""M14 record origin for showcase hygiene.

Revision ID: 0009_m14
Revises: 0008_m13
Create Date: 2026-08-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_m14"
down_revision: str | None = "0008_m13"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "ai_systems",
        sa.Column("record_origin", sa.String(32), nullable=False, server_default="manual"),
    )
    op.create_index("ix_ai_systems_record_origin", "ai_systems", ["record_origin"])
    op.execute(
        """
        UPDATE ai_systems
        SET record_origin = 'showcase'
        WHERE environment = 'lab'
          AND name IN ('Order support demo', 'Knowledge assistant demo')
        """
    )


def downgrade() -> None:
    op.drop_index("ix_ai_systems_record_origin", table_name="ai_systems")
    op.drop_column("ai_systems", "record_origin")
