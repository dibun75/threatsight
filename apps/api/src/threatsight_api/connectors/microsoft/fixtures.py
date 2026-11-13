"""Sanitized Nordic Retail rows. These identifiers are synthetic."""

from __future__ import annotations

import json

from threatsight_api.connectors.microsoft.transport import VendorRequest, VendorResponse

TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SUBSCRIPTION = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
ROLE_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
ROLE_UNKNOWN = "11111111-1111-4111-8111-111111111111"
GROUP = "22222222-2222-4222-8222-222222222222"
USER = "33333333-3333-4333-8333-333333333333"
SERVICE_PRINCIPAL = "44444444-4444-4444-8444-444444444444"
DELETED = "55555555-5555-4555-8555-555555555555"
OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
DECOY_ROLE = "99999999-9999-4999-8999-999999999999"

SUB = f"/subscriptions/{SUBSCRIPTION}"
RG = f"{SUB}/resourceGroups/retail-orders"
VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet-orders"
NIC = f"{RG}/providers/Microsoft.Network/networkInterfaces/nic-orders"
PIP = f"{RG}/providers/Microsoft.Network/publicIPAddresses/pip-orders"
NSG = f"{RG}/providers/Microsoft.Network/networkSecurityGroups/nsg-orders"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-orders"
DATA_VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-data"
LB = f"{RG}/providers/Microsoft.Network/loadBalancers/lb-orders"
GATEWAY = f"{RG}/providers/Microsoft.Network/applicationGateways/agw-orders"
APP = f"{RG}/providers/Microsoft.Web/sites/order-api"
SQL = f"{RG}/providers/Microsoft.Sql/servers/orders-data"
DANGLING = f"{RG}/providers/Microsoft.Network/networkInterfaces/nic-missing"


def azure_configuration(fixture: str = "nordic-retail") -> dict:
    return {"fixture": fixture, "microsoft_tenant_id": TENANT, "subscription_ids": [SUBSCRIPTION]}


def entra_configuration(fixture: str = "nordic-retail") -> dict:
    return {"fixture": fixture, "microsoft_tenant_id": TENANT, "subscription_ids": [SUBSCRIPTION]}


def _query(request: VendorRequest) -> str:
    if not request.json_body:
        return ""
    return str(request.json_body.get("query", "")).split(":", 1)[-1].split("\n", 1)[0]


def _skip(request: VendorRequest) -> str:
    options = (request.json_body or {}).get("options") or {}
    return str(options.get("$skipToken") or "")


def _graph(url: str) -> str:
    if "roleDefinitions" in url:
        return "definitions"
    if "roleAssignmentSchedules" in url:
        return "schedules"
    if "roleManagement/directory/roleAssignments" in url:
        return "assignments"
    if "/members" in url:
        return "members"
    if "/directoryObjects/" in url:
        return "object"
    if "Microsoft.Authorization/roleAssignments" in url:
        return "azure-roles"
    return "other"


class FixtureTransport:
    """Local double for the documented synthetic scenarios. It opens no sockets."""

    def __init__(self, scenario: str) -> None:
        self.scenario = scenario
        self.calls: list[VendorRequest] = []
        self._transient = 0

    def send_once(self, request: VendorRequest, token: str) -> VendorResponse:
        if token:
            raise CollectionError()
        self.calls.append(request)
        if self.scenario == "oversized":
            from threatsight_api.connectors.microsoft.bounds import CollectionFailure
            raise CollectionFailure("response_too_large")
        if self.scenario == "malformed":
            return VendorResponse(200, {}, None)
        if self.scenario == "throttled" and len(self.calls) == 1:
            return VendorResponse(429, {"retry-after": "2"}, None)
        if self.scenario == "transient" and self._transient < 2:
            self._transient += 1
            return VendorResponse(503, {}, None)
        if self.scenario == "forbidden" and self._required(request):
            return VendorResponse(403, {}, {"error": {"code": "AuthorizationFailed"}})
        if self.scenario == "missing-optional" and self._optional(request):
            return VendorResponse(403, {}, {"error": {"code": "Authorization_RequestDenied"}})
        if "/directoryObjects/" in request.url and DELETED in request.url:
            return VendorResponse(404, {}, None)
        return VendorResponse(200, {}, self._body(request))

    def _required(self, request: VendorRequest) -> bool:
        kind = _graph(request.url)
        return kind in {"definitions", "other"} or "ResourceGraph" in request.url

    def _optional(self, request: VendorRequest) -> bool:
        return _graph(request.url) in {"schedules", "members", "object", "azure-roles"}

    def _body(self, request: VendorRequest) -> dict:
        if "ResourceGraph" in request.url:
            return self._arg(request)
        kind = _graph(request.url)
        if self.scenario == "empty":
            return {"value": [], "data": []}
        if kind == "definitions":
            body = {"value": self._definitions()}
            if self.scenario == "excessive":
                body["@odata.nextLink"] = (
                    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
                    "?$select=id,templateId,isPrivileged&$skiptoken=next"
                )
            return body
        if kind == "assignments":
            return {"value": self._assignments()}
        if kind == "schedules":
            return {"value": [
                {"id": "schedule-group", "principalId": GROUP, "roleDefinitionId": ROLE_TEMPLATE,
                 "directoryScopeId": "/", "memberType": "Group", "assignmentType": "Active"},
                {"id": "schedule-user", "principalId": USER, "roleDefinitionId": ROLE_UNKNOWN,
                 "directoryScopeId": "/", "memberType": "Direct", "assignmentType": "Active"},
            ]}
        if kind == "members":
            return {"value": [{"id": SERVICE_PRINCIPAL, "@odata.type": "#microsoft.graph.servicePrincipal"}]}
        if kind == "object":
            return self._object(request.url)
        if kind == "azure-roles":
            return {"value": [
                {"id": f"{SUB}/providers/Microsoft.Authorization/roleAssignments/88888888-8888-4888-8888-888888888888",
                 "properties": {"principalId": SERVICE_PRINCIPAL, "roleDefinitionId": f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/{OWNER_ROLE}", "scope": SUB}},
                {"id": f"{SUB}/providers/Microsoft.Authorization/roleAssignments/99999999-9999-4999-8999-999999999990",
                 "properties": {"principalId": USER, "roleDefinitionId": f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/{DECOY_ROLE}", "scope": SUB, "roleName": "Owner"}},
            ]}
        return {"value": []}

    def _definitions(self) -> list[dict]:
        privileged = {"id": ROLE_TEMPLATE, "templateId": ROLE_TEMPLATE, "isPrivileged": True, "displayName": "synthetic-label"}
        unknown = {"id": ROLE_UNKNOWN, "templateId": ROLE_UNKNOWN, "displayName": "Global Administrator"}
        if self.scenario == "conflicting":
            return [privileged, {**privileged, "isPrivileged": False}]
        if self.scenario == "duplicates":
            return [privileged, dict(privileged)]
        return [privileged, unknown]

    def _assignments(self) -> list[dict]:
        rows = [
            {"id": "66666666-6666-4666-8666-666666666666", "principalId": GROUP, "roleDefinitionId": ROLE_TEMPLATE, "directoryScopeId": "/"},
            {"id": "77777777-7777-4777-8777-777777777777", "principalId": USER, "roleDefinitionId": ROLE_UNKNOWN, "directoryScopeId": "/"},
            {"id": "55555555-5555-4555-8555-555555555550", "principalId": DELETED, "roleDefinitionId": ROLE_TEMPLATE, "directoryScopeId": "/"},
        ]
        if self.scenario == "duplicates":
            return [rows[0], dict(rows[0])]
        return rows

    def _object(self, url: str) -> dict:
        if GROUP in url:
            return {"id": GROUP, "@odata.type": "#microsoft.graph.group", "mail": "synthetic-mailbox"}
        if USER in url:
            return {"id": USER, "@odata.type": "#microsoft.graph.user", "mail": "synthetic-mailbox", "userPrincipalName": "synthetic-sign-in"}
        if SERVICE_PRINCIPAL in url:
            return {"id": SERVICE_PRINCIPAL, "@odata.type": "#microsoft.graph.servicePrincipal", "appId": SERVICE_PRINCIPAL, "passwordCredentials": [{"secretText": "synthetic-should-drop"}]}
        return {"_status": 404}

    def _arg(self, request: VendorRequest) -> dict:
        if self.scenario == "empty":
            return {"data": [], "count": 0, "totalRecords": 0, "resultTruncated": False}
        if self.scenario == "partial":
            return {"data": [_container(SUB, "retail", "microsoft.resources/subscriptions")], "resultTruncated": True, "count": 1, "totalRecords": 2}
        query = _query(request)
        skip = _skip(request)
        if self.scenario == "excessive":
            return {"data": [_container(SUB, "retail", "microsoft.resources/subscriptions")], "$skipToken": "next"}
        rows = self._rows(query, skip)
        body = {"data": rows, "count": len(rows), "totalRecords": len(rows), "resultTruncated": False}
        if query == "resources.v1" and not skip and self.scenario == "nordic-retail":
            body["$skipToken"] = "p2"
            body["data"] = rows[:2]
            body["count"] = 2
        return body

    def _rows(self, query: str, skip: str) -> list[dict]:
        if query == "containers.v1":
            return [
                _container(SUB, "retail", "microsoft.resources/subscriptions"),
                _container(RG, "retail-orders", "microsoft.resources/subscriptions/resourcegroups"),
            ]
        if query == "resources.v1":
            rows = _resources()
            if self.scenario == "missing-optional":
                rows = [{key: value for key, value in row.items() if key not in {"publicIp", "attachedId"}} for row in rows]
            if self.scenario == "duplicates":
                return [rows[0], dict(rows[0])]
            if self.scenario == "conflicting":
                return [rows[0], {**rows[0], "name": "other-name"}]
            if self.scenario == "dangling":
                return [{**_resources()[2], "attachedId": DANGLING}]
            if skip == "p2":
                return rows[2:]
            return rows
        if query == "subnets.v1":
            return [
                {"id": VNET, "name": "vnet-orders", "subnetName": "app", "prefix": "10.8.1.0/24", "nsgId": NSG},
                {"id": VNET, "name": "vnet-orders", "subnetName": "data", "prefix": "10.8.2.0/24", "nsgId": ""},
            ]
        if query == "nsg-rules.v1":
            return [
                {"id": NSG, "ruleName": "allow-web", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "destinationPort": "443", "sourceAddress": "*", "priority": 100},
                {"id": NSG, "ruleName": "deny-rest", "direction": "Inbound", "access": "Deny", "protocol": "*", "destinationPort": "*", "sourceAddress": "*", "priority": 4000},
            ]
        return []


def _container(resource_id: str, name: str, resource_type: str) -> dict:
    return {"id": resource_id, "name": name, "type": resource_type, "location": "norwayeast", "subscriptionId": SUBSCRIPTION}


def _resources() -> list[dict]:
    tags = json.dumps({
        "service": "customer-ordering\n",
        "password": "synthetic-should-drop",
        "environment": "synthetic",
    })
    common = {"location": "norwayeast", "subscriptionId": SUBSCRIPTION, "resourceGroup": "retail-orders", "tagsText": tags}
    return [
        {"id": VNET, "name": "vnet-orders", "type": "microsoft.network/virtualnetworks", **common},
        {"id": NIC, "name": "nic-orders", "type": "microsoft.network/networkinterfaces", **common},
        {"id": PIP, "name": "pip-orders", "type": "microsoft.network/publicipaddresses", "publicIp": "203.0.113.10", "attachedId": NIC, **common},
        {"id": NSG, "name": "nsg-orders", "type": "microsoft.network/networksecuritygroups", **common},
        {"id": VM, "name": "vm-orders\r\nINFO", "type": "microsoft.compute/virtualmachines", "vmSize": "Standard_B2s", "osType": "Linux", **common},
        {"id": DATA_VM, "name": "vm-data", "type": "microsoft.compute/virtualmachines", "vmSize": "Standard_B2s", "osType": "Linux", **common},
        {"id": LB, "name": "lb-orders", "type": "microsoft.network/loadbalancers", **common},
        {"id": GATEWAY, "name": "agw-orders", "type": "microsoft.network/applicationgateways", **common},
        {"id": APP, "name": "order-api", "type": "microsoft.web/sites", **common},
        {"id": SQL, "name": "orders-data", "type": "microsoft.sql/servers", **common},
    ]


class CollectionError(Exception):
    """Raised if a fixture transport is handed a credential."""
