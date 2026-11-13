"""Phase 3C verifiable-evidence tables. Private keys are never stored here."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatsight_api.persistence.models import Base, TimestampMixin


class EvidenceSigningPolicy(TimestampMixin, Base):
    __tablename__ = "evidence_signing_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    deployment_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    kill_switch: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    pending_degraded_seconds: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("900"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))


class EvidenceSigningKey(TimestampMixin, Base):
    __tablename__ = "evidence_signing_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    deployment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'Ed25519'"))
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'file_ed25519'"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'pending'"))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("''"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    __table_args__ = (Index("ix_evidence_signing_keys_deployment_status", "deployment_id", "status"),)


class EvidenceSigningRequest(TimestampMixin, Base):
    __tablename__ = "evidence_signing_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False)
    manifest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("readiness_evidence_manifests.id", ondelete="CASCADE"), nullable=False
    )
    expected_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(200), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'pending'"))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    signature_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("evidence_signatures.id", ondelete="SET NULL"))

    __table_args__ = (
        UniqueConstraint("workspace_id", "idempotency_key", name="uq_evidence_signing_request_idem"),
        Index("ix_evidence_signing_requests_state", "state", "created_at"),
        Index("ix_evidence_signing_requests_manifest", "workspace_id", "manifest_id"),
    )


class EvidenceSignature(Base):
    __tablename__ = "evidence_signatures"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("readiness_actions.id", ondelete="CASCADE"), nullable=False)
    manifest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("readiness_evidence_manifests.id", ondelete="CASCADE"), nullable=False
    )
    envelope_version: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'threatsight.signature.v1'"))
    canonical_envelope: Mapped[str] = mapped_column(Text, nullable=False)
    envelope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_b64: Mapped[str] = mapped_column(Text, nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), ForeignKey("evidence_signing_keys.key_id"), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'Ed25519'"))
    deployment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    verification_status_at_creation: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'valid_current'"))
    previous_signature_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("evidence_signatures.id", ondelete="SET NULL"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'fixture_tested'"))
    label: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'Reference-signed evidence'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("workspace_id", "manifest_id", "signing_key_id", "envelope_version", name="uq_evidence_signature_active"),
        Index("ix_evidence_signatures_action", "workspace_id", "action_id", "signed_at"),
    )
