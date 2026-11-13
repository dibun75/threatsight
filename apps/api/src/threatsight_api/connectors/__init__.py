"""Versioned read-only connector contracts."""

from threatsight_api.connectors.sdk import (
    SDK_VERSION,
    Capability,
    CollectionEnvelope,
    ConnectorContract,
    ConnectorHealth,
    ConnectorMaturity,
    ConnectorMode,
    NormalizedRecord,
    PageRequest,
    PageResult,
    Permission,
    UnsupportedCapability,
)

__all__ = [
    "SDK_VERSION", "Capability", "CollectionEnvelope", "ConnectorContract",
    "ConnectorHealth", "ConnectorMaturity", "ConnectorMode", "NormalizedRecord",
    "PageRequest", "PageResult", "Permission", "UnsupportedCapability",
]
