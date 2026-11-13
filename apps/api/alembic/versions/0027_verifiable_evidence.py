"""Cryptographically verifiable evidence signing tables.

Revision ID: 0027_verifiable_evidence
Revises: 0026_accountable_closure
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0027_verifiable_evidence"
down_revision = "0026_accountable_closure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_signing_policies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("deployment_id", sa.String(64), nullable=False, unique=True),
        sa.Column("kill_switch", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("pending_degraded_seconds", sa.Integer(), nullable=False, server_default=sa.text("900")),
        sa.Column("maturity", sa.String(32), nullable=False, server_default=sa.text("'fixture_tested'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_table(
        "evidence_signing_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("key_id", sa.String(64), nullable=False, unique=True),
        sa.Column("deployment_id", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(32), nullable=False, server_default=sa.text("'Ed25519'")),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("public_key_fingerprint", sa.String(128), nullable=False),
        sa.Column("provider_type", sa.String(64), nullable=False, server_default=sa.text("'file_ed25519'")),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("reason", sa.String(500), nullable=False, server_default=sa.text("''")),
        sa.Column("maturity", sa.String(32), nullable=False, server_default=sa.text("'fixture_tested'")),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_evidence_signing_keys_deployment_status", "evidence_signing_keys", ["deployment_id", "status"])
    op.create_table(
        "evidence_signatures",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_id", UUID(as_uuid=True), sa.ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("manifest_id", UUID(as_uuid=True), sa.ForeignKey("readiness_evidence_manifests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("envelope_version", sa.String(32), nullable=False, server_default=sa.text("'threatsight.signature.v1'")),
        sa.Column("canonical_envelope", sa.Text(), nullable=False),
        sa.Column("envelope_digest", sa.String(64), nullable=False),
        sa.Column("signature_b64", sa.Text(), nullable=False),
        sa.Column("signing_key_id", sa.String(64), sa.ForeignKey("evidence_signing_keys.key_id"), nullable=False),
        sa.Column("algorithm", sa.String(32), nullable=False, server_default=sa.text("'Ed25519'")),
        sa.Column("deployment_id", sa.String(64), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("verification_status_at_creation", sa.String(64), nullable=False, server_default=sa.text("'valid_current'")),
        sa.Column("previous_signature_id", UUID(as_uuid=True), sa.ForeignKey("evidence_signatures.id", ondelete="SET NULL")),
        sa.Column("maturity", sa.String(32), nullable=False, server_default=sa.text("'fixture_tested'")),
        sa.Column("label", sa.String(64), nullable=False, server_default=sa.text("'Reference-signed evidence'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "manifest_id", "signing_key_id", "envelope_version", name="uq_evidence_signature_active"),
    )
    op.create_index("ix_evidence_signatures_action", "evidence_signatures", ["workspace_id", "action_id", "signed_at"])
    op.create_table(
        "evidence_signing_requests",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_id", UUID(as_uuid=True), sa.ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("manifest_id", UUID(as_uuid=True), sa.ForeignKey("readiness_evidence_manifests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("expected_digest", sa.String(64), nullable=False),
        sa.Column("requested_by", sa.String(200), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("lease_owner", sa.String(200)),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("signature_id", UUID(as_uuid=True), sa.ForeignKey("evidence_signatures.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("workspace_id", "idempotency_key", name="uq_evidence_signing_request_idem"),
    )
    op.create_index("ix_evidence_signing_requests_state", "evidence_signing_requests", ["state", "created_at"])
    op.create_index("ix_evidence_signing_requests_manifest", "evidence_signing_requests", ["workspace_id", "manifest_id"])
    op.execute(
        "INSERT INTO evidence_signing_policies (id, deployment_id, kill_switch, pending_degraded_seconds, maturity) "
        "VALUES ('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'::uuid, 'threatsight-local', false, 900, 'fixture_tested') "
        "ON CONFLICT (deployment_id) DO NOTHING"
    )


def downgrade() -> None:
    op.drop_table("evidence_signing_requests")
    op.drop_table("evidence_signatures")
    op.drop_table("evidence_signing_keys")
    op.drop_table("evidence_signing_policies")
    op.execute("DELETE FROM readiness_audit WHERE object_type IN ('signing_key', 'signing_request', 'evidence_signature', 'signing_policy')")
