from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from threatsight_api.persistence.base import Base


class LandscapeAdvisory(Base):
    __tablename__ = "landscape_advisories"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    source_key: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    canonical_url: Mapped[str] = mapped_column(String(1000), nullable=False)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False)
    vendor_advisory_id: Mapped[str] = mapped_column(String(200), nullable=False)
    cves: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    vendor_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    cvss_version: Mapped[str | None] = mapped_column(String(16))
    vex_status: Mapped[str] = mapped_column(String(32), nullable=False)
    kev_listed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    exploitation_claim: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'unknown'"))
    withdrawn: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    freshness: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'current'"))
    conflict: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    maturity: Mapped[str] = mapped_column(String(32), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'landscape-v1'"))
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    products: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    geography: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (UniqueConstraint("source_key", "external_id", name="uq_landscape_advisory_source"),)


class LandscapeCatalog(Base):
    __tablename__ = "landscape_catalog"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False)
    family: Mapped[str] = mapped_column(String(200), nullable=False)
    product: Mapped[str] = mapped_column(String(200), nullable=False)
    version_scheme: Mapped[str] = mapped_column(String(32), nullable=False)
    aliases: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))

    __table_args__ = (UniqueConstraint("vendor", "product", name="uq_landscape_catalog_product"),)
