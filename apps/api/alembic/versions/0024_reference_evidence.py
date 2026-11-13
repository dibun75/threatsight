"""Workspace-scoped synthetic evidence for the three reference services."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0024_reference_evidence"
down_revision = "0023_reference_journeys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reference_evidence_links",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_source_key", sa.String(500), nullable=False),
        sa.Column("evidence_key", sa.String(200), nullable=False),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_records.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship", sa.String(32), nullable=False),
        sa.UniqueConstraint("workspace_id", "evidence_key", name="uq_reference_evidence_key"),
    )
    from threatsight_api.investigations.reference import install

    install(op.get_bind())


def downgrade() -> None:
    op.execute(
        """
        DELETE FROM evidence_records
        WHERE source_reference LIKE 'synthetic-reference:%'
          AND id NOT IN (SELECT evidence_id FROM findings WHERE evidence_id IS NOT NULL)
        """
    )
    op.drop_table("reference_evidence_links")
