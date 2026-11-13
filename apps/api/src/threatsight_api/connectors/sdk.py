from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SDK_VERSION = "v1"


class Capability(StrEnum):
    INVENTORY = "inventory"
    CONFIGURATION_EVIDENCE = "configuration_evidence"
    HEALTH = "health"


class Permission(StrEnum):
    INVENTORY_READ = "inventory.read"
    CONFIGURATION_READ = "configuration.read"
    IDENTITY_READ = "identity.read"
    HEALTH_READ = "health.read"


class ConnectorMaturity(StrEnum):
    UNSUPPORTED = "unsupported"
    EXPERIMENTAL = "experimental"
    FIXTURE_TESTED = "fixture_tested"
    LIVE_VERIFIED = "live_verified"


class ConnectorMode(StrEnum):
    FIXTURE = "fixture"
    LIVE = "live"


class UnsupportedCapability(BaseModel):
    capability: Capability
    state: Literal["unsupported"] = "unsupported"
    reason: str = Field(min_length=1, max_length=500)


class PageRequest(BaseModel):
    cursor: str | None = Field(default=None, max_length=500)
    limit: int = Field(default=100, ge=1, le=500)


class NormalizedRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(min_length=1, max_length=64)
    external_id: str = Field(min_length=1, max_length=500)
    collected_at: datetime
    truth_state: Literal["synthetic", "fixture_tested", "live_verified", "observed", "configured", "partial", "stale", "unknown", "conflicting", "unsupported"]
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any]
    limitations: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("attributes", "provenance")
    @classmethod
    def bounded_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value, default=str).encode()) > 64_000:
            raise ValueError("normalized payload exceeds 64 KiB")
        return value


class PageResult(BaseModel):
    records: list[NormalizedRecord] = Field(max_length=500)
    next_cursor: str | None = Field(default=None, max_length=500)
    partial: bool = False
    retry_after_seconds: int | None = Field(default=None, ge=1, le=3600)
    unsupported: UnsupportedCapability | None = None


class ConnectorHealth(BaseModel):
    state: Literal["healthy", "degraded", "unavailable", "unknown", "unsupported"]
    checked_at: datetime
    detail: str = Field(max_length=500)
    safe_diagnostics: dict[str, str] = Field(default_factory=dict)


class CollectionEnvelope(BaseModel):
    sdk_version: Literal["v1"] = SDK_VERSION
    connector_key: str = Field(min_length=1, max_length=64)
    job_id: str = Field(min_length=1, max_length=64)
    idempotency_key: str = Field(min_length=1, max_length=200)
    sequence: int = Field(ge=0)
    mode: ConnectorMode
    maturity: ConnectorMaturity
    records: list[NormalizedRecord] = Field(max_length=500)
    emitted_at: datetime
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @staticmethod
    def hash_records(records: list[NormalizedRecord]) -> str:
        body = json.dumps(
            [item.model_dump(mode="json") for item in records],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(body).hexdigest()


class ConnectorContract(ABC):
    """Read-only SPI. Implementations cannot expose mutation methods."""

    sdk_version = SDK_VERSION
    connector_key: str
    capabilities: frozenset[Capability]
    permissions: frozenset[Permission]
    maturity: ConnectorMaturity
    mode: ConnectorMode
    requests_per_minute: int = 60

    @abstractmethod
    def collect(self, capability: Capability, page: PageRequest) -> PageResult:
        """Return one bounded page or an explicit unsupported state."""

    @abstractmethod
    def health(self) -> ConnectorHealth:
        """Return redacted connector health."""
