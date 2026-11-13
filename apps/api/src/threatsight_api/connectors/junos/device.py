"""Normalize allow-listed Junos replies into bounded inventory records."""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from datetime import UTC, datetime

from threatsight_api.connectors.junos.bounds import (
    CONTRACT,
    DEVICE_ID,
    HOST_INBOUND,
    INTERFACE,
    LABEL,
    MANAGEMENT_SERVICES,
    MAX_ROUTES,
    TOKEN,
    CollectionFailure,
)
from threatsight_api.connectors.junos.rpc import OPERATIONS, render
from threatsight_api.connectors.junos.target import accept_algorithm, connect_with_retry, session_expired
from threatsight_api.connectors.junos.xmlsec import local_name, parse_document
from threatsight_api.connectors.microsoft.paging import PageCursor
from threatsight_api.connectors.sdk import (
    Capability,
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
from threatsight_api.domain.enums import EvidenceFreshness
from threatsight_api.domain.freshness import classify_freshness

_SECRET_KEYS = frozenset({
    "password", "secret", "private_key", "pre-shared-key", "community", "certificate", "token", "api_key",
})


def _text(node, name: str) -> str | None:
    for child in list(node):
        if local_name(child.tag) == name and child.text:
            collapsed = " ".join(child.text.split())
            return collapsed or None
    return None


def _elements(root, name: str):
    for node in root.iter():
        if local_name(node.tag) == name:
            yield node


def _strict_prefix(value: str | None) -> str | None:
    if not value:
        return None
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return None
    if network.version != 4 or network.is_multicast:
        return None
    return str(network)


def _host_prefix(value: str | None) -> tuple[str, int] | None:
    if not value or value.count("/") != 1:
        return None
    host, length = value.split("/", 1)
    try:
        address = ipaddress.ip_address(host)
        prefix = int(length)
    except ValueError:
        return None
    if address.version != 4 or not 0 <= prefix <= 32:
        return None
    if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
        return None
    return str(address), prefix


def _usable_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4 or address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
        return None
    return str(address)


def _status(value: str | None) -> str:
    return value if value in {"up", "down"} else "unknown"


def _scrub(value):
    if isinstance(value, str):
        if len(value) > 80 or "<" in value or ">" in value or any(ord(char) < 32 for char in value):
            raise CollectionFailure("minimization_rejected")
        if "BEGIN " in value or "PRIVATE KEY" in value:
            raise CollectionFailure("minimization_rejected")
        return value
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if str(key).lower() in _SECRET_KEYS:
                raise CollectionFailure("minimization_rejected")
            cleaned[_scrub(key)] = _scrub(item)
        return cleaned
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, bool | int):
        return value
    raise CollectionFailure("minimization_rejected")


class JunosConnector(ConnectorContract):
    connector_key = "junos.device"
    capabilities = frozenset({Capability.INVENTORY, Capability.CONFIGURATION_EVIDENCE, Capability.HEALTH})
    permissions = frozenset({Permission.INVENTORY_READ, Permission.CONFIGURATION_READ, Permission.HEALTH_READ})
    requests_per_minute = 6

    def __init__(self, configuration: dict, transport, clock: Callable[[], datetime] | None = None) -> None:
        self.configuration = configuration
        self.transport = transport
        self.clock = clock or (lambda: datetime.now(UTC))
        self.mode = ConnectorMode(configuration["mode"])
        self.maturity = ConnectorMaturity.EXPERIMENTAL if self.mode == ConnectorMode.LIVE else ConnectorMaturity.FIXTURE_TESTED
        self.device_id = str(configuration["device_id"])
        if DEVICE_ID.fullmatch(self.device_id) is None:
            raise CollectionFailure("destination_refused")
        self.guard: Callable[[], None] | None = None
        self.notes: list[str] = []
        self._cursor = PageCursor(len(OPERATIONS))
        self._started = time.monotonic()
        self.opened = False
        self.produced = False
        self.stop = False
        self.force_partial = False
        self.zone_by_interface: dict[str, str] = {}
        self.zone_services: dict[str, set[str]] = {}
        self.routing_by_interface: dict[str, str] = {}
        self.interfaces: set[str] = set()

    def health(self) -> ConnectorHealth:
        local = self.mode == ConnectorMode.FIXTURE
        return ConnectorHealth(
            state="healthy" if local else "unknown",
            checked_at=self.clock(),
            detail="Fixture inventory is local" if local else "Live health does not open NETCONF",
            safe_diagnostics={"connector": self.connector_key, "mode": self.mode.value},
        )

    def collect(self, capability: Capability, page: PageRequest) -> PageResult:
        if capability != Capability.INVENTORY:
            return PageResult(
                records=[],
                unsupported=UnsupportedCapability(capability=capability, reason="Only inventory and health are implemented"),
            )
        self._check()
        self._open()
        position = self._cursor.position(page.cursor)
        if position is None:
            self._note("continuation_rejected")
            return PageResult(records=[], partial=True)
        step, _number = position
        operation = OPERATIONS[step]
        try:
            render(operation)
            payload = self.transport.rpc(operation)
        except CollectionFailure as exc:
            if exc.code == "vendor_unavailable" and self.produced:
                self._note(exc.code)
                return PageResult(records=[], next_cursor=None, partial=True)
            raise
        parsed = parse_document(payload)
        if parsed.secrets_stripped:
            self._note("secret_material_omitted")
        self._rpc_error(parsed.root)
        records = self._normalize(operation, parsed.root)
        if records:
            self.produced = True
        if self.stop:
            return PageResult(records=records, next_cursor=None)
        last = step + 1 == len(OPERATIONS)
        cursor = None if last else self._cursor.issue(step, 0, None)
        return PageResult(records=records, next_cursor=cursor, partial=bool(last and self.force_partial))

    def _check(self) -> None:
        if self.guard:
            self.guard()
        if session_expired(self._started, time.monotonic()):
            raise CollectionFailure("session_limit")

    def _open(self) -> None:
        if self.opened:
            return

        def attempt() -> None:
            self._check()
            if self.configuration.get("host_key_algorithm"):
                accept_algorithm(self.configuration.get("host_key_algorithm"))
            self.transport.start(self.configuration)

        def sleep(seconds: float) -> None:
            if seconds < 0 or seconds > 1:
                raise CollectionFailure("connection_failed")
            delays = getattr(self.transport, "reconnect_delays", None)
            if isinstance(delays, list):
                delays.append(seconds)

        connect_with_retry(attempt, sleep)
        self.opened = True

    def _note(self, value: str) -> None:
        if value not in self.notes:
            self.notes.append(value)

    def _stale(self) -> bool:
        observed = self.transport.observed_at() if hasattr(self.transport, "observed_at") else None
        if observed is None:
            return False
        return classify_freshness(observed, now=self.clock()) == EvidenceFreshness.STALE.value

    def _record(self, kind: str, external_id: str, truth: str, attributes: dict, operation: str, limitations: list[str] | None = None) -> NormalizedRecord:
        body = {key: value for key, value in attributes.items() if value is not None and value != []}
        return NormalizedRecord(
            kind=kind,
            external_id=external_id,
            collected_at=self.clock(),
            truth_state=truth,
            attributes=_scrub(body),
            provenance=_scrub({"contract": CONTRACT, "operation": operation, "mode": self.mode.value}),
            limitations=list(dict.fromkeys(limitations or []))[:40],
        )

    def _rpc_error(self, root) -> None:
        for node in _elements(root, "error-tag"):
            token = " ".join((node.text or "").split())
            if token == "access-denied":
                raise CollectionFailure("authentication_rejected")
            raise CollectionFailure("vendor_unavailable")

    def _normalize(self, operation: str, root) -> list[NormalizedRecord]:
        if operation == "hello":
            return self._hello(root)
        if operation == "get-system-information":
            return self._device(root)
        if operation == "get-config-zones":
            return self._zones(root)
        if operation == "get-config-routing":
            return self._routing(root)
        if operation == "get-interface-information":
            return self._operational_interfaces(root)
        if operation == "get-config-interfaces":
            return self._addresses(root)
        if operation == "get-config-policies":
            return self._policies(root)
        if operation == "get-route-information":
            return self._routes(root)
        if operation == "get-config-vpn":
            return self._vpn(root)
        if operation == "get-config-services":
            return self._services(root)
        raise CollectionFailure("rpc_rejected")

    def _hello(self, root) -> list[NormalizedRecord]:
        capabilities = {" ".join(node.text.split()) for node in _elements(root, "capability") if node.text}
        base_10 = "urn:ietf:params:netconf:base:1.0" in capabilities
        base_11 = "urn:ietf:params:netconf:base:1.1" in capabilities
        junos = "http://xml.juniper.net/netconf/junos/1.0" in capabilities
        if not (base_10 or base_11) or not junos:
            self.stop = True
            self._note("unsupported_capability")
            return [self._record(
                "device", f"device:{self.device_id}", "unsupported",
                {"device_id": self.device_id}, "hello", ["unsupported_capability"],
            )]
        return [self._record(
            "capability", f"capability:{self.device_id}", "observed",
            {"base_1_0": base_10, "base_1_1": base_11, "junos_1_0": junos}, "hello",
        )]

    def _device(self, root) -> list[NormalizedRecord]:
        info = next(_elements(root, "system-information"), None)
        if info is None:
            self._note("unsupported_capability")
            return []
        hostname = _text(info, "host-name")
        if hostname is None or LABEL.fullmatch(hostname) is None:
            hostname = None
        model = _text(info, "hardware-model")
        version = _text(info, "os-version")
        serial = _text(info, "serial-number")
        attributes = {
            "device_id": self.device_id,
            "model": model if model and TOKEN.fullmatch(model) else None,
            "junos_version": version if version and TOKEN.fullmatch(version) else None,
            "chassis_id": serial if serial and TOKEN.fullmatch(serial) and serial.isupper() else None,
            "informational_hostname": hostname,
        }
        truth = "stale" if self._stale() else "observed"
        limitations = ["hostname_is_not_authority"]
        if truth == "stale":
            limitations.append("stale_observation")
        return [self._record("device", f"device:{self.device_id}", truth, attributes, "get-system-information", limitations)]

    def _zones(self, root) -> list[NormalizedRecord]:
        records = []
        for zone in _elements(root, "security-zone"):
            name = _text(zone, "name")
            if name is None or LABEL.fullmatch(name) is None:
                continue
            members = []
            services: set[str] = set()
            for child in list(zone):
                if local_name(child.tag) == "interfaces":
                    member = _text(child, "name")
                    if member and INTERFACE.fullmatch(member) and member not in members:
                        members.append(member)
                        self.zone_by_interface[member] = name
            for node in zone.iter():
                if local_name(node.tag) == "name" and node.text:
                    token = " ".join(node.text.split())
                    if token in HOST_INBOUND:
                        services.add(token)
            self.zone_services[name] = services
            associated = f"interface:{self.device_id}:{members[0]}" if members else None
            records.append(self._record(
                "security_zone", f"zone:{self.device_id}:{name}", "configured",
                {
                    "name": name,
                    "member_interfaces": members,
                    "host_inbound_services": sorted(services),
                    "associated_resource_id": associated,
                    "association_state": "referenced" if associated else "unknown",
                },
                "get-config-zones",
                [] if associated else ["dangling_reference"],
            ))
        return records

    def _routing(self, root) -> list[NormalizedRecord]:
        records = []
        for instance in _elements(root, "instance"):
            name = _text(instance, "name")
            kind = _text(instance, "instance-type")
            if name is None or LABEL.fullmatch(name) is None or kind not in {"virtual-router", "vrf", "forwarding"}:
                continue
            members = []
            for child in list(instance):
                if local_name(child.tag) != "interface":
                    continue
                member = _text(child, "name")
                if member and INTERFACE.fullmatch(member):
                    members.append(member)
                    self.routing_by_interface[member] = name
            associated = f"interface:{self.device_id}:{members[0]}" if members else None
            records.append(self._record(
                "routing_instance", f"routing-instance:{self.device_id}:{name}", "configured",
                {
                    "name": name,
                    "instance_type": kind,
                    "member_interfaces": members,
                    "associated_resource_id": associated,
                    "association_state": "referenced" if associated else "unknown",
                },
                "get-config-routing",
            ))
        return records

    def _operational_interfaces(self, root) -> list[NormalizedRecord]:
        records = []
        for physical in _elements(root, "physical-interface"):
            records.extend(self._interface_node(physical, None))
            for child in list(physical):
                if local_name(child.tag) == "logical-interface":
                    records.extend(self._interface_node(child, _text(physical, "name")))
        return records

    def _interface_node(self, node, parent: str | None) -> list[NormalizedRecord]:
        name = _text(node, "name")
        if name is None or INTERFACE.fullmatch(name) is None:
            return []
        self.interfaces.add(name)
        admin = _status(_text(node, "admin-status"))
        oper = _status(_text(node, "oper-status"))
        zone = self.zone_by_interface.get(name)
        limitations = []
        if admin == "unknown" or oper == "unknown":
            truth = "unknown"
        elif admin != oper:
            truth = "conflicting"
            limitations.append("configured_operational_conflict")
        elif self._stale():
            truth = "stale"
            limitations.append("stale_observation")
        else:
            truth = "observed"
        if truth == "conflicting" and self._stale():
            limitations.append("stale_observation")
        services = self.zone_services.get(zone or "", set())
        attributes = {
            "name": name,
            "parent_interface": parent if parent and INTERFACE.fullmatch(parent) else None,
            "admin_status": admin,
            "oper_status": oper,
            "zone": zone,
            "routing_instance": self.routing_by_interface.get(name),
            "associated_resource_id": f"zone:{self.device_id}:{zone}" if zone else None,
            "association_state": "referenced" if zone else None,
        }
        if zone is not None:
            attributes["management"] = bool(services & {"ssh", "netconf"})
        else:
            limitations.append("management_classification_unknown")
        return [self._record("interface", f"interface:{self.device_id}:{name}", truth, attributes, "get-interface-information", limitations)]

    def _addresses(self, root) -> list[NormalizedRecord]:
        records = []
        parents = {child: parent for parent in root.iter() for child in list(parent)}
        for interface in _elements(root, "interface"):
            physical = _text(interface, "name")
            if physical is None or INTERFACE.fullmatch(physical) is None:
                continue
            for unit in list(interface):
                if local_name(unit.tag) != "unit":
                    continue
                number = _text(unit, "name")
                if number is None or not number.isdigit():
                    continue
                logical = f"{physical}.{int(number)}"
                if INTERFACE.fullmatch(logical) is None:
                    continue
                if logical not in self.interfaces:
                    self.interfaces.add(logical)
                    records.append(self._record(
                        "interface", f"interface:{self.device_id}:{logical}", "configured",
                        {"name": logical, "parent_interface": physical},
                        "get-config-interfaces", ["operational_state_missing"],
                    ))
                for node in unit.iter():
                    if local_name(node.tag) != "name" or local_name(parents.get(node).tag if parents.get(node) is not None else "") != "address":
                        continue
                    parsed = _host_prefix(" ".join((node.text or "").split()))
                    if parsed is None:
                        self._note("invalid_prefix")
                        continue
                    address, length = parsed
                    network = ipaddress.ip_network(f"{address}/{length}", strict=False)
                    limitations = ["prefix_has_host_bits"] if ipaddress.ip_address(address) != network.network_address else []
                    records.append(self._record(
                        "interface_address", f"address:{self.device_id}:{logical}:{address}:{length}", "configured",
                        {
                            "interface": logical,
                            "address": address,
                            "prefix_length": length,
                            "routing_instance": self.routing_by_interface.get(logical),
                            "associated_resource_id": f"interface:{self.device_id}:{logical}",
                            "association_state": "referenced",
                        },
                        "get-config-interfaces", limitations,
                    ))
        return records

    def _policies(self, root) -> list[NormalizedRecord]:
        parents = {child: parent for parent in root.iter() for child in list(parent)}
        records = []
        seen: set[tuple] = set()
        order = 0
        for node in _elements(root, "policy"):
            name = _text(node, "name")
            action = self._action(node)
            if name is None or LABEL.fullmatch(name) is None or action is None:
                continue
            parent = parents.get(node)
            from_zone = _text(parent, "from-zone-name") if parent is not None else None
            to_zone = _text(parent, "to-zone-name") if parent is not None else None
            if from_zone is None or to_zone is None or LABEL.fullmatch(from_zone) is None or LABEL.fullmatch(to_zone) is None:
                continue
            sources = self._references(node, "source-address")
            destinations = self._references(node, "destination-address")
            applications = self._references(node, "application")
            enabled = "inactive" not in {local_name(key) for key in node.attrib}
            logged = any(local_name(item.tag) == "session-init" for item in node.iter())
            signature = (from_zone, to_zone, name, action, tuple(sources), tuple(destinations), tuple(applications), enabled, logged)
            if signature in seen:
                self._note("duplicate_collapsed")
                continue
            seen.add(signature)
            order += 1
            records.append(self._record(
                "security_policy", f"policy:{self.device_id}:{from_zone}:{to_zone}:{name}", "configured",
                {
                    "name": name,
                    "order": order,
                    "from_zone": from_zone,
                    "to_zone": to_zone,
                    "source_addresses": sources,
                    "destination_addresses": destinations,
                    "applications": applications,
                    "action": action,
                    "enabled": enabled,
                    "log_session_init": logged,
                    "associated_resource_id": f"zone:{self.device_id}:{from_zone}",
                    "association_state": "referenced",
                },
                "get-config-policies",
            ))
        return records

    def _references(self, node, tag: str) -> list[str]:
        match = next((child for child in list(node) if local_name(child.tag) == "match"), None)
        if match is None:
            return []
        values = []
        for child in list(match):
            if local_name(child.tag) != tag or not child.text:
                continue
            text = " ".join(child.text.split())
            if "/" in text:
                prefix = _strict_prefix(text)
                if prefix is None:
                    self._note("invalid_prefix")
                    continue
                values.append(prefix)
            elif LABEL.fullmatch(text):
                values.append(text)
            else:
                self._note("invalid_prefix")
        return values

    def _action(self, node) -> str | None:
        then = next((child for child in list(node) if local_name(child.tag) == "then"), None)
        if then is None:
            return None
        names = {local_name(child.tag) for child in list(then)}
        if "permit" in names:
            return "allow"
        if "deny" in names or "reject" in names:
            return "deny"
        return None

    def _routes(self, root) -> list[NormalizedRecord]:
        found: dict[str, dict] = {}
        for table in _elements(root, "route-table"):
            if _text(table, "table-name") != "inet.0":
                self._note("route_table_skipped")
                continue
            for route in list(table):
                if local_name(route.tag) != "rt":
                    continue
                prefix = _strict_prefix(_text(route, "rt-destination"))
                if prefix is None:
                    self._note("invalid_prefix")
                    continue
                if prefix in found:
                    self._note("duplicate_collapsed")
                    continue
                hop = _usable_ip(next(( _text(item, "to") for item in _elements(route, "nh")), None))
                via = next((_text(item, "via") for item in _elements(route, "nh")), None)
                protocol = next((_text(item, "protocol-name") for item in _elements(route, "rt-entry")), None)
                if via and INTERFACE.fullmatch(via) is None:
                    via = None
                if protocol and TOKEN.fullmatch(protocol) is None:
                    protocol = None
                found[prefix] = {"prefix": prefix, "next_hop": hop, "interface": via, "protocol": protocol}
        selected = [found[key] for key in sorted(found)]
        limitations = []
        if len(selected) > MAX_ROUTES:
            selected = selected[:MAX_ROUTES]
            self.force_partial = True
            self._note("route_limit")
            limitations.append("route_limit")
        records = []
        stale = self._stale()
        for item in selected:
            item_limitations = list(limitations)
            truth = "stale" if stale else "observed"
            if item["next_hop"] is None:
                truth = "unknown"
                item_limitations.append("next_hop_unknown")
            if stale and truth == "unknown":
                item_limitations.append("stale_observation")
            via = item["interface"]
            records.append(self._record(
                "route", f"route:{self.device_id}:{item['prefix']}", truth,
                {
                    "destination_prefix": item["prefix"],
                    "next_hop": item["next_hop"],
                    "interface": via,
                    "protocol": item["protocol"],
                    "routing_table": "inet.0",
                    "associated_resource_id": f"interface:{self.device_id}:{via}" if via else None,
                    "association_state": "referenced" if via else "unknown",
                },
                "get-route-information", item_limitations,
            ))
        return records

    def _vpn(self, root) -> list[NormalizedRecord]:
        binds: dict[str, tuple[str, str]] = {}
        for vpn in _elements(root, "vpn"):
            tunnel = _text(vpn, "name")
            bind = _text(vpn, "bind-interface")
            gateway = next((_text(item, "gateway") or (" ".join(item.text.split()) if item.text else None) for item in list(vpn.iter()) if local_name(item.tag) == "gateway"), None)
            if tunnel and LABEL.fullmatch(tunnel) and bind and INTERFACE.fullmatch(bind) and gateway and LABEL.fullmatch(gateway):
                binds[gateway] = (tunnel, bind)
        records = []
        for gateway in _elements(root, "gateway"):
            name = _text(gateway, "name")
            if name is None or LABEL.fullmatch(name) is None:
                continue
            peer = _usable_ip(_text(gateway, "address"))
            external = _text(gateway, "external-interface")
            if external and INTERFACE.fullmatch(external) is None:
                external = None
            state = _text(gateway, "ike-sa-state")
            operational = state.lower() if state in {"UP", "DOWN"} else None
            tunnel, bind = binds.get(name, (None, None))
            truth = "stale" if operational and self._stale() else "observed" if operational else "configured"
            limitations = ["secret_material_omitted"]
            if operational is None:
                limitations.append("operational_state_unknown")
            records.append(self._record(
                "vpn_gateway", f"vpn:{self.device_id}:{name}", truth,
                {
                    "name": name,
                    "tunnel": tunnel,
                    "peer": peer,
                    "external_interface": external,
                    "bind_interface": bind,
                    "operational_state": operational,
                    "associated_resource_id": f"interface:{self.device_id}:{bind}" if bind else None,
                    "association_state": "referenced" if bind else "unknown",
                },
                "get-config-vpn", limitations,
            ))
        return records

    def _services(self, root) -> list[NormalizedRecord]:
        names: set[str] = set()
        for services in _elements(root, "services"):
            for child in list(services):
                name = local_name(child.tag)
                if name in MANAGEMENT_SERVICES:
                    names.add(name)
                if name == "web-management":
                    names.update(local_name(item.tag) for item in list(child) if local_name(item.tag) in {"http", "https"})
                if name == "netconf":
                    names.add("netconf")
        for node in _elements(root, "snmp"):
            names.add("snmp")
        records = []
        for name in sorted(names):
            zones = sorted(zone for zone, services in self.zone_services.items() if name in services)
            limitations = ["configuration_is_not_reachability"]
            if name in {"telnet", "ftp"}:
                limitations.append("insecure_service_configured")
            if not zones:
                limitations.append("source_context_unknown")
            records.append(self._record(
                "management_service", f"management:{self.device_id}:{name}", "configured",
                {"service": name, "allowed_zones": zones, "reachability": "not_observed"},
                "get-config-services", limitations,
            ))
        return records
