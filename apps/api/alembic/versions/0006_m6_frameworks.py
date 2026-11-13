"""M6 framework catalog provenance and curated items.

Revision ID: 0006_m6
Revises: 0005_m5
Create Date: 2026-08-27
"""

from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from threatsight_api.frameworks.catalog import CATALOG_ITEMS, CATALOG_VERSION

revision: str = "0006_m6"
down_revision: str | None = "0005_m5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("framework_references", sa.Column("statement", sa.Text()))
    op.add_column("framework_references", sa.Column("source_kind", sa.String(32)))
    op.add_column("framework_references", sa.Column("catalog_version", sa.String(32)))
    op.add_column(
        "framework_references",
        sa.Column("informational_only", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    conn = op.get_bind()
    for item in CATALOG_ITEMS:
        row = conn.execute(
            sa.text(
                "SELECT id FROM framework_references WHERE framework_key = :key AND reference_code = :code"
            ),
            {"key": item.framework_key, "code": item.reference_code},
        ).fetchone()
        if row is None:
            conn.execute(
                sa.text(
                    """
                    INSERT INTO framework_references
                    (id, framework_key, reference_code, title, locator, statement, source_kind, catalog_version, informational_only)
                    VALUES
                    (:id, :key, :code, :title, :locator, :statement, :source_kind, :version, true)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "key": item.framework_key,
                    "code": item.reference_code,
                    "title": item.title[:300],
                    "locator": item.locator,
                    "statement": item.statement,
                    "source_kind": item.source_kind,
                    "version": CATALOG_VERSION,
                },
            )
        else:
            conn.execute(
                sa.text(
                    """
                    UPDATE framework_references
                    SET title = :title,
                        locator = :locator,
                        statement = :statement,
                        source_kind = :source_kind,
                        catalog_version = :version,
                        informational_only = true
                    WHERE id = :id
                    """
                ),
                {
                    "id": row[0],
                    "title": item.title[:300],
                    "locator": item.locator,
                    "statement": item.statement,
                    "source_kind": item.source_kind,
                    "version": CATALOG_VERSION,
                },
            )


def downgrade() -> None:
    op.drop_column("framework_references", "informational_only")
    op.drop_column("framework_references", "catalog_version")
    op.drop_column("framework_references", "source_kind")
    op.drop_column("framework_references", "statement")
