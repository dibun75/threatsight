"""Mark the seeded workspace as the synthetic public demo and retire its runner credentials.

Every unrevoked credential in that workspace is revoked, including leftover test runners.
Active registrations whose names start with runner- are marked revoked. The disconnected
synthetic reference runner stays disconnected. Downgrade drops the classification column
and does not restore credentials.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_public_demo"
down_revision: str | None = "0016_threat_correlation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEMO_WORKSPACE = "00000000-0000-4000-8000-000000000010"


def upgrade() -> None:
    op.add_column(
        "workspaces",
        sa.Column("classification", sa.String(length=32), nullable=False, server_default="unspecified"),
    )
    op.execute(
        "UPDATE workspaces SET classification = 'synthetic_demo' "
        "WHERE key = 'default' AND id = '" + DEMO_WORKSPACE + "'"
    )
    op.execute(
        "UPDATE runner_credentials AS credential SET revoked_at = CURRENT_TIMESTAMP "
        "FROM runner_registrations AS runner "
        "WHERE credential.runner_id = runner.id AND credential.revoked_at IS NULL "
        "AND runner.workspace_id = '" + DEMO_WORKSPACE + "'"
    )
    op.execute(
        "UPDATE runner_registrations SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP "
        "WHERE workspace_id = '" + DEMO_WORKSPACE + "' "
        "AND status = 'active' AND name ~ '^runner-'"
    )


def downgrade() -> None:
    op.drop_column("workspaces", "classification")
