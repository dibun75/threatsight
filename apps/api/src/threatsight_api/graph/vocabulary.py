"""Approved Phase 2 graph vocabulary.

Node and edge types describe source records and deterministic relationships.
They do not state exposure, reachability, control effectiveness, or compromise.
"""

from __future__ import annotations

NODE_TYPES: tuple[str, ...] = (
    "business_service",
    "cloud_subscription",
    "resource_group",
    "cloud_resource",
    "application_service",
    "database_service",
    "load_balancer",
    "identity",
    "group",
    "service_principal",
    "role",
    "role_assignment",
    "network",
    "subnet",
    "public_address",
    "network_interface",
    "device",
    "logical_interface",
    "security_zone",
    "route",
    "security_policy",
    "vpn",
    "site",
    "software_version",
)

# Direction is documented in docs/reference/graph.md. There is no untyped relationship.
EDGE_TYPES: tuple[str, ...] = (
    "contains",
    "member_of",
    "assigned_to",
    "attached_to",
    "connected_to",
    "routes_to",
    "in_zone",
    "governed_by",
    "permits_reference",
    "denies_reference",
    "peers_with",
    "depends_on",
    "serves",
    "administered_through",
    "sourced_from",
)

MATURITIES: tuple[str, ...] = ("synthetic", "fixture_tested", "live_verified")
EVIDENCE_MODES: tuple[str, ...] = ("observed", "configured", "inferred", "manual")
LIFECYCLES: tuple[str, ...] = ("active", "stale", "missing", "superseded", "conflicting")
FRESHNESS: tuple[str, ...] = ("fresh", "stale", "untested")
CONFIDENCE: tuple[str, ...] = ("stated", "derived", "unknown")
SNAPSHOT_STATUSES: tuple[str, ...] = ("building", "completed", "failed", "cancelled")
MEMBER_ROLES: tuple[str, ...] = ("entry", "dependency", "identity", "network", "administration")
CONFLICT_TYPES: tuple[str, ...] = (
    "configured_observed",
    "ambiguous_identity",
    "dangling_reference",
    "unsupported",
    "partial_omission",
    "stale_source",
    "duplicate_address",
    "conflicting_assertion",
)

NOT_A_FINDING = "not_an_exposure_finding"
ABSENCE_IS_NOT_EVIDENCE = "absence_is_not_negative_evidence"
NOT_REACHABILITY = "not_a_reachability_finding"
NOT_CONTROL = "not_a_control_verdict"

SITE_KEY_RULE = "shared-site-key-v1"
SITE_KEY_VERSION = "1"
PARENT_RULE = "same-connector-parent-v1"
ARM_RULE = "azure-arm-prefix-v1"
GROUP_RULE = "group-member-v1"
ASSIGNMENT_RULE = "assignment-target-v1"
POLICY_RULE = "policy-reference-v1"
ADDRESS_RULE = "documented-address-v1"
SOFTWARE_RULE = "device-software-v1"
DEPENDENCY_RULE = "fixture-service-dependency-v1"

KIND_NODE: dict[str, str] = {
    "subscription": "cloud_subscription",
    "resource_group": "resource_group",
    "virtual_network": "network",
    "network": "network",
    "subnet": "subnet",
    "vlan": "subnet",
    "public_ip": "public_address",
    "network_interface": "network_interface",
    "uplink": "network_interface",
    "virtual_machine": "cloud_resource",
    "app_service": "application_service",
    "sql_server": "database_service",
    "load_balancer": "load_balancer",
    "application_gateway": "load_balancer",
    "organization": "site",
    "device": "device",
    "vpn": "vpn",
    "vpn_gateway": "vpn",
    "security_zone": "security_zone",
    "route": "route",
    "security_policy": "security_policy",
    "network_security_rule": "security_policy",
    "network_security_group": "security_policy",
    "directory_role": "role",
    "role_assignment": "role_assignment",
    "azure_role_assignment": "role_assignment",
    "business_service": "business_service",
}

UNMAPPED_KINDS = frozenset({
    "group_membership",
    "collection_status",
    "collection_gap",
    "capability",
    "device_status",
    "routing_instance",
    "management_service",
})


def sql_in(column: str, values: tuple[str, ...]) -> str:
    quoted = ",".join(f"'{item}'" for item in values)
    return f"{column} IN ({quoted})"


def source_key(connector: str, external_id: str) -> str:
    return f"{connector}:{external_id}"[:500]
