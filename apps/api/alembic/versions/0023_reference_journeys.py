"""Synthetic journeys for privileged administration and remote access."""

from __future__ import annotations

from alembic import op

revision = "0023_reference_journeys"
down_revision = "0022_radar_collection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from threatsight_api.investigations.reference import install

    install(op.get_bind())


def downgrade() -> None:
    op.execute("DELETE FROM analysis_results WHERE rule_id IN ('reference-privileged-chain-v1', 'reference-remote-chain-v1')")
    op.execute(
        "DELETE FROM graph_edges WHERE source_key IN "
        "('synthetic.fixture:edge:privileged-admin-gateway', 'synthetic.fixture:edge:remote-access-vpn')"
    )
    op.execute("DELETE FROM reference_journeys WHERE chain_key IN ('privileged-administration', 'remote-access')")
