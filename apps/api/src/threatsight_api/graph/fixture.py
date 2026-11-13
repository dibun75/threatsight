"""Synthetic Nordic Retail graph fixture.

Every record is synthetic and fixture_tested. Nothing here is a customer,
a live network, or an exposure finding. Addresses are documentation ranges.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from threatsight_api.graph.sanitize import GraphFailure
from threatsight_api.graph.vocabulary import source_key

AZURE = "azure.resource_graph"
ENTRA = "entra.graph"
MERAKI = "meraki.dashboard"
JUNOS = "junos.device"
SYNTH = "synthetic.fixture"

SUB = "/subscriptions/11111111-1111-4111-8111-111111111111"
RG = f"{SUB}/resourceGroups/synth-order"
VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/synth-vnet"
SUBNET = f"{VNET}/subnets/synth-app"
PIP = f"{RG}/providers/Microsoft.Network/publicIPAddresses/synth-pip"
APP = f"{RG}/providers/Microsoft.Web/sites/synth-orders"
SQL = f"{RG}/providers/Microsoft.Sql/servers/synth-orders-db"
APPGW = f"{RG}/providers/Microsoft.Network/applicationGateways/synth-gw"
ORDERING = "service:customer-ordering"
ADMIN = "service:privileged-administration"
REMOTE = "service:remote-access"
FRESH = datetime(2026, 10, 1, tzinfo=UTC)
STALE = datetime(2020, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class FixtureBundle:
    name: str
    records: list[dict]
    memberships: list[tuple[str, str, str]]
    dependency_pairs: list[tuple[str, str]]
    partial: bool


def load_fixture(name: str) -> FixtureBundle:
    if name == "correlation":
        return _correlation_bundle()
    if name not in {"nordic-retail", "partial"}:
        raise GraphFailure("fixture_rejected")
    records = _records()
    if name == "partial":
        records = [item for item in records if item["external_id"] != "device:Q2XX-SYNTH-0001"]
        records.append(_record(MERAKI, "collection_status", "status:partial", "partial", {}, contract="collection.v1"))
    return FixtureBundle(
        name=name,
        records=records,
        memberships=_memberships(),
        dependency_pairs=[(source_key(AZURE, APP), source_key(AZURE, SQL))],
        partial=name == "partial",
    )


def _memberships() -> list[tuple[str, str, str]]:
    ordering = source_key(SYNTH, ORDERING)
    admin = source_key(SYNTH, ADMIN)
    remote = source_key(SYNTH, REMOTE)
    return [
        (ordering, source_key(AZURE, PIP), "entry"),
        (ordering, source_key(AZURE, APP), "dependency"),
        (ordering, source_key(AZURE, SQL), "dependency"),
        (ordering, source_key(AZURE, SUBNET), "network"),
        (ordering, source_key(ENTRA, "user:synth-admin"), "identity"),
        (admin, source_key(ENTRA, "ra:synth-admin"), "administration"),
        (admin, source_key(AZURE, SUB), "administration"),
        (admin, source_key(JUNOS, "iface:fxp0"), "administration"),
        (remote, source_key(MERAKI, "vpn:2001"), "network"),
        (remote, source_key(JUNOS, "vpn:synth-branch"), "network"),
        (remote, source_key(MERAKI, "network:2001"), "network"),
        (remote, source_key(JUNOS, "zone:synth-junos:untrust"), "network"),
    ]


def _records() -> list[dict]:
    return [
        _record(AZURE, "subscription", SUB, "fixture_tested", {"name": "synth-order-sub"}, contract="subscriptions.v1"),
        _record(AZURE, "resource_group", RG, "fixture_tested", {"name": "synth-order", "associated_resource_id": SUB}, contract="resource-groups.v1"),
        _record(AZURE, "virtual_network", VNET, "fixture_tested", {"name": "synth-vnet", "associated_resource_id": RG}, contract="networks.v1"),
        _record(AZURE, "subnet", SUBNET, "fixture_tested", {"name": "synth-app", "associated_resource_id": VNET, "prefix": "10.8.0.0/24"}, contract="subnets.v1"),
        _record(AZURE, "public_ip", PIP, "fixture_tested", {"name": "synth-pip", "address": "203.0.113.10", "associated_resource_id": APPGW}, contract="public-ips.v1"),
        _record(AZURE, "application_gateway", APPGW, "fixture_tested", {"name": "synth-gw", "associated_resource_id": SUBNET}, contract="gateways.v1"),
        _record(AZURE, "app_service", APP, "fixture_tested", {"name": "synth-orders", "associated_resource_id": RG}, contract="sites.v1"),
        _record(AZURE, "sql_server", SQL, "fixture_tested", {"name": "synth-orders-db", "associated_resource_id": RG}, contract="sql.v1"),
        _record(AZURE, "network_interface", f"{RG}/providers/Microsoft.Network/networkInterfaces/synth-nic", "live_verified", {"name": "synth-nic", "associated_resource_id": SUBNET}, contract="nics.v1"),
        _record(ENTRA, "principal", "user:synth-admin", "configured", {"name": "synth-admin", "principal_type": "user"}, contract="directory-object.v1"),
        _record(ENTRA, "principal", "group:synth-admins", "configured", {"name": "synth-admins", "principal_type": "group"}, contract="directory-object.v1"),
        _record(ENTRA, "group_membership", "gm:synth-admin", "configured", {"group_id": "group:synth-admins", "member_id": "user:synth-admin"}, contract="group-members.v1"),
        _record(ENTRA, "directory_role", "role:synth-priv", "configured", {"name": "synth-privileged"}, contract="directory-role.v1"),
        _record(ENTRA, "role_assignment", "ra:synth-admin", "configured", {"name": "synth-assignment", "principal_id": "user:synth-admin", "role_id": "role:synth-priv"}, contract="role-assignment.v1"),
        _record(MERAKI, "organization", "org:1001", "configured", {"name": "synth-meraki-org"}, contract="organization.v1"),
        _record(MERAKI, "network", "network:2001", "configured", {"name": "synth-branch", "associated_resource_id": "org:1001", "site_key": "synth-site-hq"}, contract="network.v1"),
        _record(MERAKI, "device", "device:Q2XX-SYNTH-0001", "observed", {"name": "synth-branch-device", "associated_resource_id": "network:2001"}, contract="device.v1"),
        _record(MERAKI, "vlan", "vlan:2001:10", "configured", {"name": "synth-users", "associated_resource_id": "network:2001"}, contract="vlan.v1"),
        _record(MERAKI, "vpn", "vpn:2001", "configured", {"name": "synth-auto-vpn", "associated_resource_id": "network:2001"}, contract="vpn.v1"),
        _record(MERAKI, "uplink", "uplink:Q2XX:wan1", "observed", {"name": "wan1", "display_name": "shared-label", "address": "203.0.113.50", "associated_resource_id": "device:Q2XX-SYNTH-0001"}, contract="uplink.v1"),
        _record(MERAKI, "collection_gap", "gap:client-vpn", "unsupported", {"name": "client-vpn"}, contract="gap.v1"),
        _record(JUNOS, "device", "device:synth-junos-edge-01", "observed", {"name": "synth-junos-edge-01", "site_key": "synth-site-hq", "software_version": "23.4R1-synth"}, contract="junos-rpc-v1"),
        _record(JUNOS, "interface", "iface:ge-0/0/0", "conflicting", {"name": "ge-0/0/0", "admin_status": "up", "oper_status": "down", "associated_resource_id": "device:synth-junos-edge-01"}, contract="junos-rpc-v1"),
        _record(JUNOS, "interface", "iface:ge-0/0/0.0", "configured", {"name": "ge-0/0/0.0", "address": "203.0.113.11", "associated_resource_id": "iface:ge-0/0/0"}, contract="junos-rpc-v1"),
        _record(JUNOS, "interface", "iface:ge-0/0/1.0", "configured", {"name": "ge-0/0/1.0", "display_name": "shared-label", "address": "203.0.113.50", "associated_resource_id": "device:synth-junos-edge-01"}, contract="junos-rpc-v1"),
        _record(JUNOS, "interface", "iface:fxp0", "configured", {"name": "fxp0", "address": "10.255.0.1", "associated_resource_id": "device:synth-junos-edge-01"}, contract="junos-rpc-v1"),
        _record(JUNOS, "security_zone", "zone:synth-junos:untrust", "configured", {"name": "untrust", "associated_resource_id": "device:synth-junos-edge-01"}, contract="junos-rpc-v1"),
        _record(JUNOS, "security_zone", "zone:synth-junos:trust", "configured", {"name": "trust", "associated_resource_id": "device:synth-junos-edge-01"}, contract="junos-rpc-v1"),
        _record(JUNOS, "route", "route:default", "stale", {"name": "default", "associated_resource_id": "iface:ge-0/0/0.0"}, contract="junos-rpc-v1", collected_at=STALE),
        _record(JUNOS, "security_policy", "policy:edge-deny", "configured", {"name": "edge-deny", "action": "deny", "reference_ids": ["zone:synth-junos:untrust", "zone:synth-junos:missing"]}, contract="junos-rpc-v1"),
        _record(JUNOS, "vpn_gateway", "vpn:synth-branch", "configured", {"name": "synth-branch-vpn", "associated_resource_id": "device:synth-junos-edge-01"}, contract="junos-rpc-v1"),
        _record(JUNOS, "management_service", "mgmt:netconf", "configured", {"name": "netconf"}, contract="junos-rpc-v1"),
        _record(SYNTH, "business_service", ORDERING, "synthetic", {"name": "Customer ordering"}, contract="synthetic-service.v1"),
        _record(SYNTH, "business_service", ADMIN, "synthetic", {"name": "Privileged administration"}, contract="synthetic-service.v1"),
        _record(SYNTH, "business_service", REMOTE, "synthetic", {"name": "Remote access and site connectivity"}, contract="synthetic-service.v1"),
    ]


def _correlation_bundle() -> FixtureBundle:
    ordering = source_key(SYNTH, "service:customer-ordering")
    admin = source_key(SYNTH, "service:privileged-administration")
    remote = source_key(SYNTH, "service:remote-access")
    exact = "device:exact-widget"
    ranged = "device:range-widget"
    alias = "device:alias-widget"
    meraki = "device:meraki-ap"
    junos = "device:junos-edge"
    missing = "device:missing-widget"
    conflict = "device:conflict-widget"
    unrelated = "device:unrelated"
    cloud = "vm:synthetic-web"
    records = [
        _record(SYNTH, "business_service", "service:customer-ordering", "synthetic", {"name": "Customer ordering"}, contract="synthetic-service.v1"),
        _record(SYNTH, "business_service", "service:privileged-administration", "synthetic", {"name": "Privileged administration"}, contract="synthetic-service.v1"),
        _record(SYNTH, "business_service", "service:remote-access", "synthetic", {"name": "Remote access"}, contract="synthetic-service.v1"),
        _record(SYNTH, "device", exact, "configured", {"vendor": "acme", "product": "widget", "version": "1.2.3", "cpe": "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"}, contract="correlation.v1"),
        _record(SYNTH, "device", ranged, "configured", {"vendor": "acme", "product": "widget", "version": "1.2.5", "cpe": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}, contract="correlation.v1"),
        _record(SYNTH, "device", alias, "configured", {"vendor": "acme", "product": "synth-widget", "version": "1.2.4"}, contract="correlation.v1"),
        _record(MERAKI, "device", meraki, "observed", {"firmware_family": "mr", "firmware": "29.1", "version": "29.1"}, contract="device.v1"),
        _record(JUNOS, "device", junos, "observed", {"software_version": "23.4R1-synth"}, contract="junos-rpc-v1"),
        _record(SYNTH, "device", missing, "configured", {"vendor": "acme", "product": "widget"}, contract="correlation.v1"),
        _record(SYNTH, "device", conflict, "configured", {"vendor": "acme", "product": "widget", "version": "1.2.3", "cpe": "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"}, contract="correlation.v1"),
        _record(SYNTH, "device", unrelated, "configured", {"vendor": "other", "product": "unrelated", "version": "9.9.9"}, contract="correlation.v1"),
        _record(AZURE, "virtual_machine", cloud, "configured", {"cloud_service": "synthetic.web", "cloud_scope": "resource"}, contract="correlation.v1"),
        _record(SYNTH, "device", "device:purl-helper", "configured", {"vendor": "acme", "product": "helper", "version": "2.0.0", "purl": "pkg:generic/acme/helper@2.0.0"}, contract="correlation.v1"),
    ]
    memberships = [
        (ordering, source_key(SYNTH, exact), "dependency"),
        (admin, source_key(MERAKI, meraki), "administration"),
        (remote, source_key(JUNOS, junos), "network"),
    ]
    return FixtureBundle("correlation", records, memberships, [], False)


def _record(connector: str, kind: str, external_id: str, truth: str, attributes: dict, *, contract: str, collected_at: datetime = FRESH) -> dict:
    return {
        "connector_key": connector,
        "contract": contract,
        "external_id": external_id,
        "kind": kind,
        "truth_state": truth,
        "collected_at": collected_at,
        "attributes": attributes,
        "limitations": ["synthetic_fixture"],
        "envelope_maturity": "fixture_tested",
        "envelope_mode": "fixture",
    }
