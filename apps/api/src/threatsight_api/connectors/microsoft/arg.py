"""Read-only Azure Resource Graph inventory. Queries are constants."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from threatsight_api.connectors.microsoft.bounds import (
    ARM_API,
    clean_arm_id,
    clean_tags,
    continuation_rejected,
    safe_label,
)
from threatsight_api.connectors.microsoft.paging import PageCursor
from threatsight_api.connectors.microsoft.transport import VendorRequest, pause, register_queries, transmit
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

ARG_URL = f"https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version={ARM_API}"
QUERIES = {
    "containers.v1": """// threatsight:containers.v1
ResourceContainers
| where type in~ ('microsoft.resources/subscriptions','microsoft.resources/subscriptions/resourcegroups')
| project id, name, type, location, subscriptionId
| order by id asc
""",
    "resources.v1": """// threatsight:resources.v1
Resources
| where type in~ ('microsoft.network/virtualnetworks','microsoft.network/networkinterfaces','microsoft.network/publicipaddresses','microsoft.network/networksecuritygroups','microsoft.compute/virtualmachines','microsoft.network/loadbalancers','microsoft.network/applicationgateways','microsoft.web/sites','microsoft.sql/servers')
| project id, name, type, location, resourceGroup, subscriptionId, tagsText = tostring(tags), vmSize = tostring(properties.hardwareProfile.vmSize), osType = tostring(properties.storageProfile.osDisk.osType), publicIp = tostring(properties.ipAddress), attachedId = tostring(properties.ipConfiguration.id)
| order by id asc
""",
    "subnets.v1": """// threatsight:subnets.v1
Resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand subnet = properties.subnets
| project id, name, location, resourceGroup, subscriptionId, subnetName = tostring(subnet.name), prefix = tostring(subnet.properties.addressPrefix), nsgId = tostring(subnet.properties.networkSecurityGroup.id)
| order by id asc, subnetName asc
""",
    "nsg-rules.v1": """// threatsight:nsg-rules.v1
Resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| project id, name, location, resourceGroup, subscriptionId, ruleName = tostring(rule.name), direction = tostring(rule.properties.direction), access = tostring(rule.properties.access), protocol = tostring(rule.properties.protocol), destinationPort = tostring(rule.properties.destinationPortRange), sourceAddress = tostring(rule.properties.sourceAddressPrefix), priority = toint(rule.properties.priority)
| order by id asc, ruleName asc
""",
}
KINDS = {
    "microsoft.resources/subscriptions": "subscription",
    "microsoft.resources/subscriptions/resourcegroups": "resource_group",
    "microsoft.network/virtualnetworks": "virtual_network",
    "microsoft.network/networkinterfaces": "network_interface",
    "microsoft.network/publicipaddresses": "public_ip",
    "microsoft.network/networksecuritygroups": "network_security_group",
    "microsoft.compute/virtualmachines": "virtual_machine",
    "microsoft.network/loadbalancers": "load_balancer",
    "microsoft.network/applicationgateways": "application_gateway",
    "microsoft.web/sites": "app_service",
    "microsoft.sql/servers": "sql_server",
}
CHOICES = {
    "direction": {"inbound": "inbound", "outbound": "outbound"},
    "access": {"allow": "allow", "deny": "deny"},
    "protocol": {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "*": "any"},
}


class AzureResourceGraphConnector(ConnectorContract):
    connector_key = "azure.resource_graph"
    capabilities = frozenset({Capability.INVENTORY, Capability.HEALTH})
    permissions = frozenset({Permission.INVENTORY_READ, Permission.HEALTH_READ})
    requests_per_minute = 15

    def __init__(self, configuration: dict, transport, token: str = "", clock: Callable[[], datetime] | None = None) -> None:
        self.mode = ConnectorMode(configuration["mode"])
        self.maturity = ConnectorMaturity.LIVE_VERIFIED if self.mode == ConnectorMode.LIVE else ConnectorMaturity.FIXTURE_TESTED
        self.transport = transport
        self.token = token
        self.clock = clock or (lambda: datetime.now(UTC))
        self.tenant = str(uuid.UUID(str(configuration["microsoft_tenant_id"])))
        self.subscriptions = [str(uuid.UUID(str(item))) for item in configuration["subscription_ids"]]
        self.guard: Callable[[], None] | None = None
        self.notes: list[str] = []
        self._cursor = PageCursor(len(QUERIES))
        self._steps = list(QUERIES)

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(
            state="healthy" if self.mode == ConnectorMode.FIXTURE else "unknown",
            checked_at=self.clock(),
            detail="Fixture inventory is local" if self.mode == ConnectorMode.FIXTURE else "Live health does not call Azure",
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
        response = transmit(self.transport, self._request(step, number), self.token, pause)
        if response.status == 429:
            return PageResult(records=[], partial=True, retry_after_seconds=_retry_after(response.headers))
        if response.status in {401, 403}:
            return PageResult(records=[], unsupported=UnsupportedCapability(capability=capability, reason="Azure Reader access is not available for the requested subscriptions"))
        if response.status != 200 or not isinstance(response.payload, dict) or not isinstance(response.payload.get("data"), list):
            from threatsight_api.connectors.microsoft.bounds import CollectionFailure
            raise CollectionFailure("malformed_response")
        records = [item for item in (self._normalize(step, row) for row in response.payload["data"]) if item is not None]
        continuation = response.payload.get("$skipToken")
        truncated = bool(response.payload.get("resultTruncated"))
        if truncated and not continuation:
            self._note("truncated_result")
            continuation = None
        elif continuation is not None and continuation_rejected(continuation):
            self._note("continuation_rejected")
            continuation = None
            truncated = True
        return PageResult(records=records, next_cursor=self._cursor.issue(step, number, continuation if isinstance(continuation, str) else None), partial=truncated)

    def _request(self, step: int, number: int) -> VendorRequest:
        query_id = self._steps[step]
        options: dict[str, object] = {"$top": 100, "resultFormat": "objectArray"}
        token = self._cursor.token(step, number)
        if token:
            options["$skipToken"] = token
        return VendorRequest("POST", ARG_URL, "arm", {
            "query": QUERIES[query_id],
            "subscriptions": self.subscriptions,
            "options": options,
        })

    def _normalize(self, step: int, row: object) -> NormalizedRecord | None:
        if not isinstance(row, dict):
            self._note("malformed_row")
            return None
        query_id = self._steps[step]
        if query_id == "subnets.v1":
            return self._subnet(row)
        if query_id == "nsg-rules.v1":
            return self._rule(row)
        resource_id = clean_arm_id(row.get("id"))
        kind = KINDS.get(str(row.get("type", "")).lower())
        if resource_id is None or kind is None:
            self._note("malformed_row")
            return None
        attributes = {
            "name": safe_label(row.get("name")) or "unknown",
            "resource_type": str(row.get("type", "")).lower(),
            "location": safe_label(row.get("location"), 40).lower(),
            "resource_group": safe_label(row.get("resourceGroup"), 90).lower(),
            "subscription_id": _uuid(row.get("subscriptionId")),
            "tags": clean_tags(row.get("tagsText")),
        }
        if kind == "virtual_machine":
            attributes["vm_size"] = safe_label(row.get("vmSize"), 40)
            attributes["os_type"] = safe_label(row.get("osType"), 20).lower()
        if kind == "public_ip":
            address = safe_label(row.get("publicIp"), 45)
            attributes["address"] = address or "unknown"
            associated = clean_arm_id(row.get("attachedId"))
            attributes["associated_resource_id"] = associated or ""
            attributes["association_state"] = "referenced" if associated else "unknown"
            if not address:
                self._note("address_unavailable")
        attributes = {key: value for key, value in attributes.items() if value != "" and value != {}}
        return self._record(kind, resource_id, attributes, query_id)

    def _subnet(self, row: dict) -> NormalizedRecord | None:
        network = clean_arm_id(row.get("id"))
        name = safe_label(row.get("subnetName"), 80)
        if network is None or not name:
            self._note("malformed_row")
            return None
        nsg = clean_arm_id(row.get("nsgId"))
        return self._record("subnet", f"{network}/subnets/{name}", {
            "name": name,
            "network_id": network,
            "prefix": safe_label(row.get("prefix"), 40) or "unknown",
            "associated_resource_id": nsg or "",
            "association_state": "referenced" if nsg else "unknown",
        }, "subnets.v1")

    def _rule(self, row: dict) -> NormalizedRecord | None:
        group = clean_arm_id(row.get("id"))
        name = safe_label(row.get("ruleName"), 80)
        if group is None or not name:
            self._note("malformed_row")
            return None
        priority = row.get("priority")
        return self._record("network_security_rule", f"{group}/rules/{name}", {
            "name": name,
            "network_security_group_id": group,
            "direction": CHOICES["direction"].get(safe_label(row.get("direction")).lower(), "unknown"),
            "access": CHOICES["access"].get(safe_label(row.get("access")).lower(), "unknown"),
            "protocol": CHOICES["protocol"].get(safe_label(row.get("protocol")).lower(), "unknown"),
            "destination_port": safe_label(row.get("destinationPort"), 32) or "unknown",
            "source": safe_label(row.get("sourceAddress"), 80) or "unknown",
            "priority": priority if isinstance(priority, int) and 0 <= priority <= 4096 else "unknown",
        }, "nsg-rules.v1")

    def _record(self, kind: str, external_id: str, attributes: dict, query_id: str) -> NormalizedRecord:
        attributes = {key: value for key, value in attributes.items() if value != ""}
        return NormalizedRecord(
            kind=kind,
            external_id=external_id,
            collected_at=self.clock(),
            truth_state="live_verified" if self.mode == ConnectorMode.LIVE else "fixture_tested",
            attributes=attributes,
            provenance={
                "source": "azure_resource_graph",
                "contract": query_id,
                "api_version": ARM_API,
                "mode": self.mode.value,
                "microsoft_tenant_id": self.tenant,
            },
        )

    def _check(self) -> None:
        if self.guard is not None:
            self.guard()

    def _note(self, value: str) -> None:
        if value not in self.notes and len(self.notes) < 40:
            self.notes.append(value)


def _uuid(value: object) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        return "unknown"


register_queries(set(QUERIES.values()))


def _retry_after(headers: dict[str, str]) -> int:
    try:
        value = int(str(headers.get("retry-after", "30")).strip())
    except ValueError:
        value = 30
    return min(3600, max(1, value))
