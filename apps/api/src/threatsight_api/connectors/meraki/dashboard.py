"""Read-only Meraki Dashboard inventory for one explicit organization scope."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urlsplit

from threatsight_api.connectors.meraki.bounds import (
    HA_ROLES,
    INTERFACES,
    MAX_COLLECTION_SECONDS,
    MAX_HTTP_CALLS,
    MAX_VENDOR_PAGES,
    NETWORK_ID,
    ORG_ID,
    PAGE_SIZE,
    PRODUCTS,
    SERIAL,
    UPLINK_STATUS,
    CollectionFailure,
    clean_identifier,
    clean_ip,
    clean_subnet,
    public_label,
)
from threatsight_api.connectors.meraki.live import collection_origin
from threatsight_api.connectors.meraki.paging import next_link
from threatsight_api.connectors.meraki.transport import VendorRequest, transmit
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
from threatsight_api.domain.freshness import DEFAULT_WINDOW_DAYS, classify_freshness

CONTRACT = "meraki-dashboard-api-v1.75.1"


class MerakiDashboardConnector(ConnectorContract):
    connector_key = "meraki.dashboard"
    capabilities = frozenset({Capability.INVENTORY, Capability.HEALTH})
    permissions = frozenset({Permission.INVENTORY_READ, Permission.HEALTH_READ})
    requests_per_minute = 10

    def __init__(self, configuration: dict, transport, api_key: str = "", clock: Callable[[], datetime] | None = None) -> None:
        self.mode = ConnectorMode(configuration["mode"])
        self.maturity = ConnectorMaturity.LIVE_VERIFIED if self.mode == ConnectorMode.LIVE else ConnectorMaturity.FIXTURE_TESTED
        self.transport = transport
        self.token = api_key
        self.clock = clock or (lambda: datetime.now(UTC))
        self.organizations = [str(item) for item in configuration["organization_ids"]]
        self.origin = collection_origin()
        self.guard: Callable[[], None] | None = None
        self.notes: list[str] = []
        self._seen: set[str] = set()
        self._emitted: set[str] = set()
        self._names: dict[str, str] = {}
        self._cursor = PageCursor(1 + len(self.organizations))
        self._started = time.monotonic()
        self._calls = 0

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(
            state="healthy" if self.mode == ConnectorMode.FIXTURE else "unknown",
            checked_at=self.clock(),
            detail="Fixture inventory is local" if self.mode == ConnectorMode.FIXTURE else "Live health does not call Meraki",
            safe_diagnostics={"connector": self.connector_key, "mode": self.mode.value},
        )

    def collect(self, capability: Capability, page: PageRequest) -> PageResult:
        if capability != Capability.INVENTORY:
            return PageResult(records=[], unsupported=UnsupportedCapability(capability=capability, reason="Only inventory and health are implemented"))
        position = self._cursor.position(page.cursor)
        if position is None:
            self._note("continuation_rejected")
            return PageResult(records=[], partial=True)
        step, number = position
        self._check()
        if step == 0:
            return self._directory(number)
        return self._organization(self.organizations[step - 1], step, number)

    def _directory(self, number: int) -> PageResult:
        path = "/api/v1/organizations"
        response, failed = self._get(path, number)
        if isinstance(failed, PageResult):
            return failed
        if response.status in {401, 403}:
            return PageResult(records=[], unsupported=UnsupportedCapability(capability=Capability.INVENTORY, reason="Read-only Dashboard access is not available"))
        if response.status != 200 or not isinstance(response.payload, list):
            raise CollectionFailure("vendor_unavailable", response.status >= 500)
        outside = 0
        for row in response.payload:
            if not isinstance(row, dict):
                continue
            identifier = clean_identifier(row.get("id"), ORG_ID)
            if identifier is None:
                self._note("invalid_identifier")
                continue
            if identifier not in self.organizations:
                outside += 1
                continue
            self._seen.add(identifier)
            label = public_label(row.get("name"))
            if label:
                self._names[identifier] = label
        records = [self._organization_record(item) for item in self.organizations if item in self._seen and item not in self._emitted]
        self._emitted.update(item for item in self.organizations if item in self._seen)
        if outside:
            self._note("unselected_organizations_ignored")
        link = self._continuation(response.headers.get("link"), path)
        if link == "rejected":
            return PageResult(records=records, partial=True)
        if isinstance(link, str):
            if number + 1 >= MAX_VENDOR_PAGES:
                self._note("page_limit")
                return PageResult(records=records, partial=True)
            return PageResult(records=records, next_cursor=self._cursor.issue(0, number, link))
        records.extend(self._organization_record(item) for item in self.organizations if item not in self._seen)
        return PageResult(records=records, next_cursor=self._cursor.issue(0, number, None))

    def _organization(self, org: str, step: int, number: int) -> PageResult:
        records: list[NormalizedRecord] = []
        if number or org not in self._seen:
            return PageResult(records=records, next_cursor=self._cursor.issue(step, number, None))
        networks = self._rows(f"/api/v1/organizations/{org}/networks")
        if isinstance(networks, PageResult):
            return networks
        network_ids: list[str] = []
        for row in networks:
            record = self._network(org, row)
            if record is None:
                continue
            records.append(record)
            if "appliance" in record.attributes.get("product_types", []):
                network_ids.append(str(record.attributes["network_id"]))
        devices = self._rows(f"/api/v1/organizations/{org}/devices")
        if isinstance(devices, PageResult):
            devices.records = [*records, *devices.records]
            return devices
        for row in devices:
            record = self._device(org, row)
            if record is not None:
                records.append(record)
        for endpoint, parser in (
            (f"/api/v1/organizations/{org}/devices/statuses", self._status),
            (f"/api/v1/organizations/{org}/appliance/uplink/statuses", self._uplink),
            (f"/api/v1/organizations/{org}/appliance/vpn/statuses", self._vpn),
        ):
            fetched = self._rows(endpoint, optional=True)
            if isinstance(fetched, PageResult):
                fetched.records = [*records, *fetched.records]
                return fetched
            if isinstance(fetched, NormalizedRecord):
                records.append(fetched)
                continue
            for row in fetched:
                parsed = parser(org, row)
                if parsed is None:
                    continue
                records.extend(parsed if isinstance(parsed, list) else [parsed])
        for network_id in network_ids[:4]:
            fetched = self._rows(f"/api/v1/networks/{network_id}/appliance/vlans", optional=True)
            if isinstance(fetched, PageResult):
                fetched.records = [*records, *fetched.records]
                return fetched
            if isinstance(fetched, NormalizedRecord):
                records.append(fetched)
                continue
            for row in fetched:
                record = self._vlan(network_id, row)
                if record is not None:
                    records.append(record)
        return PageResult(records=records, next_cursor=self._cursor.issue(step, number, None))

    def _rows(self, path: str, optional: bool = False) -> list[dict] | NormalizedRecord | PageResult:
        collected: list[dict] = []
        link: str | None = None
        for page in range(MAX_VENDOR_PAGES):
            response, failed = self._get(path, page, link)
            if isinstance(failed, PageResult):
                return failed
            if response.status in {400, 404} and optional:
                return self._gap(path, "product_unavailable")
            if response.status in {401, 403} and optional:
                return self._gap(path, "permission_unavailable")
            if response.status != 200 or not isinstance(response.payload, list):
                raise CollectionFailure("vendor_unavailable", response.status >= 500)
            collected.extend(row for row in response.payload if isinstance(row, dict))
            continuation = self._continuation(response.headers.get("link"), path)
            if continuation == "rejected":
                return PageResult(records=[], partial=True)
            if continuation is None:
                return collected
            link = continuation
        self._note("page_limit")
        return PageResult(records=[], partial=True)

    def _get(self, path: str, page: int, link: str | None = None) -> tuple[object, PageResult | None]:
        self._check()
        self._calls += 1
        if self._calls > MAX_HTTP_CALLS or time.monotonic() - self._started > MAX_COLLECTION_SECONDS:
            self._note("call_limit")
            return None, PageResult(records=[], partial=True)
        stored = self._cursor.token(0, page) if page else None
        target = link or stored or f"{self.origin}{path}?perPage={PAGE_SIZE}"
        if path.endswith("/appliance/vlans"):
            target = f"{self.origin}{path}"
        response = transmit(self.transport, VendorRequest("GET", target), self.token, _pause)
        if response.status == 429:
            self._note("rate_limited")
            return None, PageResult(records=[], partial=True, retry_after_seconds=_retry_after(response.headers))
        return response, None

    def _continuation(self, header: str | None, path: str) -> str | None:
        try:
            return next_link(header, origin=self.origin, path=path)
        except CollectionFailure:
            self._note("continuation_rejected")
            return "rejected"

    def _organization_record(self, identifier: str) -> NormalizedRecord:
        visible = identifier in self._seen
        attributes: dict[str, str] = {"organization_id": identifier, "scope_state": "selected"}
        if self._names.get(identifier):
            attributes["name"] = self._names[identifier]
        return self._record(
            "organization",
            f"organization:{identifier}",
            attributes,
            [] if visible else ["missing_or_inaccessible"],
            "observed" if visible else "unknown",
        )

    def _network(self, org: str, row: dict) -> NormalizedRecord | None:
        identifier = clean_identifier(row.get("id"), NETWORK_ID)
        owner = clean_identifier(row.get("organizationId"), ORG_ID)
        if identifier is None or owner != org:
            self._note("invalid_identifier")
            return None
        products = [item for item in row.get("productTypes", []) if item in PRODUCTS] if isinstance(row.get("productTypes"), list) else []
        attributes = {"organization_id": org, "network_id": identifier, "product_types": products}
        label = public_label(row.get("name"))
        if label:
            attributes["name"] = label
        zone = public_label(row.get("timeZone"), 40)
        if zone:
            attributes["time_zone"] = zone
        return self._record("network", f"network:{identifier}", attributes, [], "observed", f"organization:{org}")

    def _device(self, org: str, row: dict) -> NormalizedRecord | None:
        serial = clean_identifier(row.get("serial"), SERIAL)
        if serial is None:
            self._note("invalid_identifier")
            return None
        attributes = {"organization_id": org, "serial": serial}
        model = public_label(row.get("model"), 40)
        firmware = public_label(row.get("firmware"), 40)
        product = row.get("productType") if row.get("productType") in PRODUCTS else None
        network = clean_identifier(row.get("networkId"), NETWORK_ID)
        address = clean_ip(row.get("lanIp"))
        if model:
            attributes["model"] = model
        if firmware:
            attributes["firmware"] = firmware
        if product:
            attributes["product_type"] = product
        if network:
            attributes["network_id"] = network
        if address:
            attributes["lan_ip"] = address
        elif row.get("lanIp"):
            self._note("invalid_address")
        limitations = ["invalid_address"] if row.get("lanIp") and not address else []
        return self._record("device", f"device:{serial}", attributes, limitations, "observed", f"network:{network}" if network else None)

    def _status(self, org: str, row: dict) -> NormalizedRecord | None:
        serial = clean_identifier(row.get("serial"), SERIAL)
        if serial is None:
            return None
        reported = _timestamp(row.get("lastReportedAt"))
        attributes = {"organization_id": org, "serial": serial}
        network = clean_identifier(row.get("networkId"), NETWORK_ID)
        public = clean_ip(row.get("publicIp"))
        lan = clean_ip(row.get("lanIp"))
        if network:
            attributes["network_id"] = network
        if public:
            attributes["public_ip"] = public
        if lan:
            attributes["lan_ip"] = lan
        if reported:
            attributes["source_reported_at"] = reported.isoformat()
        state = _choice(row.get("status"))
        if state:
            attributes["status"] = state
        limitations = []
        if row.get("publicIp") and not public:
            limitations.append("invalid_address")
            self._note("invalid_address")
        truth = "stale" if reported and classify_freshness(reported, now=self.clock(), window_days=DEFAULT_WINDOW_DAYS) == "STALE" else "observed"
        return self._record("device_status", f"device-status:{serial}", attributes, limitations, truth, f"device:{serial}")

    def _uplink(self, org: str, row: dict) -> list[NormalizedRecord] | None:
        serial = clean_identifier(row.get("serial"), SERIAL)
        if serial is None or not isinstance(row.get("uplinks"), list):
            return None
        reported = _timestamp(row.get("lastReportedAt"))
        truth = "stale" if reported and classify_freshness(reported, now=self.clock(), window_days=DEFAULT_WINDOW_DAYS) == "STALE" else "observed"
        records = []
        for item in row["uplinks"]:
            if not isinstance(item, dict) or item.get("interface") not in INTERFACES:
                continue
            interface = str(item["interface"])
            attributes = {"organization_id": org, "serial": serial, "interface": interface}
            if item.get("status") in UPLINK_STATUS:
                attributes["status"] = item["status"]
            for source, target in (("ip", "ip"), ("publicIp", "public_ip"), ("gateway", "gateway")):
                parsed = clean_ip(item.get(source))
                if parsed:
                    attributes[target] = parsed
                elif item.get(source):
                    self._note("invalid_address")
            if reported:
                attributes["source_reported_at"] = reported.isoformat()
            role = row.get("highAvailability", {}).get("role") if isinstance(row.get("highAvailability"), dict) else None
            if role in HA_ROLES:
                attributes["ha_role"] = role
            records.append(self._record("uplink", f"uplink:{serial}:{interface}", attributes, [], truth, f"device:{serial}"))
        return records or None

    def _vpn(self, org: str, row: dict) -> NormalizedRecord | None:
        network = clean_identifier(row.get("networkId"), NETWORK_ID)
        if network is None:
            return None
        attributes: dict[str, object] = {"organization_id": org, "network_id": network}
        serial = clean_identifier(row.get("deviceSerial"), SERIAL)
        mode = _choice(row.get("vpnMode"))
        if serial:
            attributes["serial"] = serial
        if mode:
            attributes["vpn_mode"] = mode
        subnets = []
        for item in row.get("exportedSubnets") or []:
            if isinstance(item, dict):
                subnet = clean_subnet(item.get("subnet"))
                if subnet:
                    subnets.append(subnet)
                elif item.get("subnet"):
                    self._note("invalid_subnet")
        if subnets:
            attributes["exported_subnets"] = subnets
        peers = []
        for item in row.get("merakiVpnPeers") or []:
            if isinstance(item, dict):
                peer = clean_identifier(item.get("networkId"), NETWORK_ID)
                if peer:
                    peers.append(peer)
        if peers:
            attributes["peer_network_ids"] = peers
        public = []
        for item in row.get("thirdPartyVpnPeers") or []:
            if isinstance(item, dict):
                parsed = clean_ip(item.get("publicIp"))
                if parsed:
                    public.append(parsed)
        if public:
            attributes["third_party_public_ips"] = public
        limitations = ["invalid_subnet"] if any(isinstance(item, dict) and item.get("subnet") and not clean_subnet(item.get("subnet")) for item in row.get("exportedSubnets") or []) else []
        return self._record("vpn", f"vpn:{network}", attributes, limitations, "observed", f"network:{network}")

    def _vlan(self, network: str, row: dict) -> NormalizedRecord | None:
        identifier = public_label(row.get("id"), 20)
        if not identifier or not identifier.isdigit():
            return None
        subnet = clean_subnet(row.get("subnet"))
        address = clean_ip(row.get("applianceIp"))
        attributes: dict[str, object] = {"network_id": network, "vlan_id": identifier}
        limitations = []
        if subnet:
            attributes["subnet"] = subnet
        elif row.get("subnet"):
            limitations.append("invalid_subnet")
            self._note("invalid_subnet")
        if address:
            attributes["appliance_ip"] = address
        elif row.get("applianceIp"):
            limitations.append("invalid_address")
        return self._record("vlan", f"vlan:{network}:{identifier}", attributes, limitations, "configured", f"network:{network}")

    def _gap(self, path: str, limitation: str) -> NormalizedRecord:
        self._note(limitation)
        endpoint = path.removeprefix("/api/v1/")
        return self._record("collection_gap", f"gap:{endpoint}", {"endpoint": endpoint}, [limitation], "unsupported")

    def _record(self, kind: str, external_id: str, attributes: dict, limitations: list[str], truth: str, associated: str | None = None) -> NormalizedRecord:
        body = dict(attributes)
        if associated:
            body["associated_resource_id"] = associated
        observed = truth if self.mode == ConnectorMode.LIVE else ("stale" if truth == "stale" else "unknown" if truth == "unknown" else "unsupported" if truth == "unsupported" else "fixture_tested")
        return NormalizedRecord(
            kind=kind,
            external_id=external_id,
            collected_at=self.clock(),
            truth_state=observed,  # type: ignore[arg-type]
            attributes=body,
            provenance={"source": self.connector_key, "mode": self.mode.value, "contract": CONTRACT, "origin": urlsplit(self.origin).hostname or "api.meraki.com"},
            limitations=limitations,
        )

    def _check(self) -> None:
        if self.guard:
            self.guard()

    def _note(self, value: str) -> None:
        if value not in self.notes:
            self.notes.append(value)


def _pause(seconds: float) -> None:
    del seconds


def _retry_after(headers: dict[str, str]) -> int:
    try:
        value = int(float(headers.get("retry-after", "1")))
    except ValueError:
        value = 1
    return min(3600, max(1, value))


def _choice(value: object) -> str:
    text = public_label(value, 20).lower()
    if text and all(ch.isascii() and (ch.islower() or ch == " ") for ch in text):
        return text
    return ""


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)
