"""Read-only Entra role context and optional Azure role assignments."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

from threatsight_api.connectors.microsoft.bounds import (
    ROLE_API,
    CollectionFailure,
    clean_arm_id,
    graph_next_rejected,
    safe_label,
)
from threatsight_api.connectors.microsoft.paging import PageCursor
from threatsight_api.connectors.microsoft.transport import VendorRequest, pause, transmit
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

GRAPH = "https://graph.microsoft.com/v1.0"
ROLE_SELECT = frozenset({"id", "templateId", "isPrivileged"})
ASSIGNMENT_SELECT = frozenset({"id", "principalId", "roleDefinitionId", "directoryScopeId"})
SCHEDULE_SELECT = frozenset({"id", "principalId", "roleDefinitionId", "directoryScopeId", "memberType", "assignmentType"})
OBJECT_SELECT = frozenset({"id"})
MEMBER_SELECT = frozenset({"id"})
PRINCIPAL_TYPES = {
    "#microsoft.graph.user": "user",
    "#microsoft.graph.serviceprincipal": "service_principal",
    "#microsoft.graph.group": "group",
}
PRIVILEGED_AZURE_ROLES = frozenset({
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "b24988ac-6180-42a0-ab88-20f7382dd24c",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168",
})
STEPS = ("definitions", "schedules", "assignments", "principals", "members", "azure")


class EntraConnector(ConnectorContract):
    connector_key = "entra.identity"
    capabilities = frozenset({Capability.INVENTORY, Capability.HEALTH})
    permissions = frozenset({Permission.IDENTITY_READ, Permission.HEALTH_READ})
    requests_per_minute = 30

    def __init__(self, configuration: dict, transport, token: str = "", arm_token: str = "", clock: Callable[[], datetime] | None = None) -> None:
        self.mode = ConnectorMode(configuration["mode"])
        self.maturity = ConnectorMaturity.LIVE_VERIFIED if self.mode == ConnectorMode.LIVE else ConnectorMaturity.FIXTURE_TESTED
        self.transport = transport
        self.token = token
        self.arm_token = arm_token or token
        self.clock = clock or (lambda: datetime.now(UTC))
        self.tenant = str(uuid.UUID(str(configuration["microsoft_tenant_id"])))
        self.subscriptions = [str(uuid.UUID(str(item))) for item in configuration.get("subscription_ids", [])]
        self.guard: Callable[[], None] | None = None
        self.notes: list[str] = []
        self._cursor = PageCursor(len(STEPS))
        self._privileged: dict[str, bool | None] = {}
        self._basis: dict[str, str] = {}
        self._activation: dict[str, str] = {}
        self._pending: list[str] = []
        self._groups: list[str] = []
        self._seen: set[str] = set()
        self._subscription_index = 0

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(
            state="healthy" if self.mode == ConnectorMode.FIXTURE else "unknown",
            checked_at=self.clock(),
            detail="Fixture identity context is local" if self.mode == ConnectorMode.FIXTURE else "Live health does not call Microsoft Graph",
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
        name = STEPS[step]
        if name == "principals":
            return self._principals(step, number)
        if name == "members":
            return self._members(step, number)
        if name == "azure":
            return self._azure(step, number)
        return self._graph_page(step, number, name)

    def _graph_page(self, step: int, number: int, name: str) -> PageResult:
        select = {"definitions": ROLE_SELECT, "schedules": SCHEDULE_SELECT, "assignments": ASSIGNMENT_SELECT}[name]
        path = {"definitions": "roleDefinitions", "schedules": "roleAssignmentSchedules", "assignments": "roleAssignments"}[name]
        saved = self._cursor.token(step, number)
        url = saved or f"{GRAPH}/roleManagement/directory/{path}?$select={','.join(sorted(select))}&$top=100"
        self._check()
        response = transmit(self.transport, VendorRequest("GET", url, "graph"), self.token, pause)
        if response.status == 429:
            return PageResult(records=[], partial=True, retry_after_seconds=_retry_after(response.headers))
        if response.status in {401, 403}:
            if name == "schedules":
                self._note("privileged_eligibility_unsupported")
                return PageResult(records=[], next_cursor=self._cursor.issue(step, number, None))
            return PageResult(records=[], unsupported=UnsupportedCapability(capability=Capability.INVENTORY, reason="Directory role read permission is not available"))
        rows = _rows(response)
        records: list[NormalizedRecord] = []
        for row in rows:
            if name == "definitions":
                item = self._definition(row)
            elif name == "schedules":
                item = self._schedule(row)
            else:
                item = self._assignment(row)
            if item is not None:
                records.append(item)
        return PageResult(records=records, next_cursor=self._cursor.issue(step, number, self._next(response.payload, select)), partial=False)

    def _principals(self, step: int, number: int) -> PageResult:
        records: list[NormalizedRecord] = []
        for _ in range(10):
            if not self._pending:
                break
            principal = self._pending.pop(0)
            self._check()
            response = transmit(
                self.transport,
                VendorRequest("GET", f"{GRAPH}/directoryObjects/{principal}?$select=id", "graph"),
                self.token,
                pause,
            )
            records.append(self._principal(principal, response))
        continuation = "principal-page" if self._pending else None
        return PageResult(records=records, next_cursor=self._cursor.issue(step, number, continuation))

    def _members(self, step: int, number: int) -> PageResult:
        records: list[NormalizedRecord] = []
        if self._groups:
            group = self._groups.pop(0)
            self._check()
            response = transmit(
                self.transport,
                VendorRequest("GET", f"{GRAPH}/groups/{group}/members?$select=id&$top=20", "graph"),
                self.token,
                pause,
            )
            if response.status in {401, 403}:
                self._note("group_expansion_unsupported")
            elif response.status == 429:
                return PageResult(records=[], partial=True, retry_after_seconds=_retry_after(response.headers))
            else:
                for row in _rows(response)[:20]:
                    member = _uuid(row.get("id")) if isinstance(row, dict) else None
                    if member is None:
                        self._note("malformed_row")
                        continue
                    member_type = PRINCIPAL_TYPES.get(str(row.get("@odata.type", "")).lower(), "unknown")
                    records.append(self._record("group_membership", f"{group}:{member}", {
                        "group_id": group, "member_id": member, "principal_type": member_type, "relationship": "transitive",
                    }, "group-members.v1"))
                if len(_rows(response)) > 20:
                    self._note("truncated_result")
        continuation = "member-page" if self._groups else None
        return PageResult(records=records, next_cursor=self._cursor.issue(step, number, continuation))

    def _azure(self, step: int, number: int) -> PageResult:
        if not self.subscriptions:
            self._note("azure_scope_not_configured")
            return PageResult(records=[], next_cursor=self._cursor.issue(step, number, None))
        saved = self._cursor.token(step, number)
        if saved == "next-subscription":
            saved = None
        subscription = self.subscriptions[min(self._subscription_index, len(self.subscriptions) - 1)]
        url = (
            f"https://management.azure.com/subscriptions/{subscription}"
            f"/providers/Microsoft.Authorization/roleAssignments?api-version={ROLE_API}"
        )
        if saved:
            if _arm_next_rejected(saved, subscription):
                self._note("continuation_rejected")
                return PageResult(records=[], partial=True)
            url = saved
        self._check()
        response = transmit(self.transport, VendorRequest("GET", url, "arm"), self.arm_token, pause)
        if response.status == 429:
            return PageResult(records=[], partial=True, retry_after_seconds=_retry_after(response.headers))
        if response.status in {401, 403}:
            self._note("azure_role_assignments_unsupported")
            return PageResult(records=[], next_cursor=self._cursor.issue(step, number, None))
        records = [item for item in (self._azure_assignment(row) for row in _rows(response)) if item is not None]
        next_url = response.payload.get("nextLink") if isinstance(response.payload, dict) else None
        if next_url and _arm_next_rejected(str(next_url), subscription):
            self._note("continuation_rejected")
            next_url = None
        if not next_url and self._subscription_index + 1 < len(self.subscriptions):
            self._subscription_index += 1
            return PageResult(records=records, next_cursor=self._cursor.issue(step, number, "next-subscription"))
        return PageResult(records=records, next_cursor=self._cursor.issue(step, number, str(next_url) if next_url else None))

    def _definition(self, row: object) -> NormalizedRecord | None:
        if not isinstance(row, dict):
            self._note("malformed_row")
            return None
        role_id = _uuid(row.get("templateId")) or _uuid(row.get("id"))
        if role_id is None:
            self._note("malformed_row")
            return None
        privileged = row.get("isPrivileged") if isinstance(row.get("isPrivileged"), bool) else None
        self._privileged[role_id] = privileged
        return self._record("directory_role", role_id, {
            "role_template_id": role_id,
            "privileged": "unknown" if privileged is None else privileged,
        }, "role-definitions.v1")

    def _schedule(self, row: object) -> None:
        if not isinstance(row, dict):
            self._note("malformed_row")
            return None
        principal = _uuid(row.get("principalId"))
        if principal is None:
            self._note("malformed_row")
            return None
        basis = {"group": "group", "direct": "direct"}.get(safe_label(row.get("memberType")).lower(), "unknown")
        activation = {"active": "active", "eligible": "eligible"}.get(safe_label(row.get("assignmentType")).lower(), "unknown")
        if principal in self._basis and self._basis[principal] != basis:
            self._basis[principal] = "unknown"
            self._note("conflicting_source_row")
        else:
            self._basis[principal] = basis
        self._activation[principal] = activation
        return None

    def _assignment(self, row: object) -> NormalizedRecord | None:
        if not isinstance(row, dict):
            self._note("malformed_row")
            return None
        assignment_id = _uuid(row.get("id"))
        principal = _uuid(row.get("principalId"))
        role_id = _uuid(row.get("roleDefinitionId"))
        if assignment_id is None or principal is None or role_id is None:
            self._note("malformed_row")
            return None
        if principal not in self._seen:
            self._seen.add(principal)
            self._pending.append(principal)
        privileged = self._privileged.get(role_id)
        return self._record("role_assignment", assignment_id, {
            "principal_id": principal,
            "role_template_id": role_id,
            "scope": _scope(row.get("directoryScopeId")),
            "assignment_basis": self._basis.get(principal, "unknown"),
            "assignment_type": self._activation.get(principal, "unknown"),
            "privileged": "unknown" if privileged is None else privileged,
            "relationship": "direct" if self._basis.get(principal) == "direct" else "group" if self._basis.get(principal) == "group" else "unknown",
        }, "role-assignments.v1")

    def _principal(self, principal: str, response) -> NormalizedRecord:
        if response.status == 404:
            self._note("deleted_or_dangling")
            return self._record("principal", principal, {"principal_type": "unknown"}, "directory-object.v1", truth="unknown")
        if response.status in {401, 403}:
            self._note("principal_type_unsupported")
            return self._record("principal", principal, {"principal_type": "unknown"}, "directory-object.v1", truth="unknown")
        if response.status == 429:
            self._pending.insert(0, principal)
            raise CollectionFailure("rate_limited", True)
        row = response.payload if isinstance(response.payload, dict) else {}
        principal_type = PRINCIPAL_TYPES.get(str(row.get("@odata.type", "")).lower(), "unknown")
        if principal_type == "unknown":
            self._note("principal_type_unknown")
        if principal_type == "group" and principal not in self._groups:
            self._groups.append(principal)
        attributes = {"principal_type": principal_type}
        app_id = _uuid(row.get("appId"))
        if principal_type == "service_principal" and app_id:
            attributes["app_id"] = app_id
        return self._record("principal", principal, attributes, "directory-object.v1", truth="unknown" if principal_type == "unknown" else None)

    def _azure_assignment(self, row: object) -> NormalizedRecord | None:
        if not isinstance(row, dict):
            self._note("malformed_row")
            return None
        properties = row.get("properties") if isinstance(row.get("properties"), dict) else row
        role_id = _uuid(str(properties.get("roleDefinitionId", "")).rsplit("/", 1)[-1])
        principal = _uuid(properties.get("principalId"))
        assignment_id = clean_arm_id(row.get("id"))
        scope = clean_arm_id(properties.get("scope"))
        if role_id is None or principal is None or assignment_id is None:
            self._note("malformed_row")
            return None
        if role_id not in PRIVILEGED_AZURE_ROLES:
            self._note("non_privileged_assignments_excluded")
            return None
        return self._record("azure_role_assignment", assignment_id, {
            "principal_id": principal,
            "role_definition_id": role_id,
            "scope": scope or "unknown",
            "assignment_basis": "direct",
            "privileged": True,
            "relationship": "direct",
        }, "azure-role-assignments.v1")

    def _record(self, kind: str, external_id: str, attributes: dict, contract: str, truth: str | None = None) -> NormalizedRecord:
        return NormalizedRecord(
            kind=kind,
            external_id=external_id[:500],
            collected_at=self.clock(),
            truth_state=truth or ("live_verified" if self.mode == ConnectorMode.LIVE else "fixture_tested"),
            attributes=attributes,
            provenance={
                "source": "microsoft_graph" if contract != "azure-role-assignments.v1" else "azure_authorization",
                "contract": contract,
                "mode": self.mode.value,
                "microsoft_tenant_id": self.tenant,
            },
        )

    def _next(self, payload: dict | None, select: frozenset[str]) -> str | None:
        link = payload.get("@odata.nextLink") if isinstance(payload, dict) else None
        if not link:
            return None
        if graph_next_rejected(link, select):
            self._note("continuation_rejected")
            return None
        return str(link)

    def _check(self) -> None:
        if self.guard is not None:
            self.guard()

    def _note(self, value: str) -> None:
        if value not in self.notes and len(self.notes) < 40:
            self.notes.append(value)


def _rows(response) -> list:
    if response.status != 200 or not isinstance(response.payload, dict):
        raise CollectionFailure("malformed_response")
    rows = response.payload.get("value")
    if not isinstance(rows, list):
        raise CollectionFailure("malformed_response")
    return rows


def _uuid(value: object) -> str | None:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        return None


def _scope(value: object) -> str:
    text = safe_label(value, 200)
    if text == "/":
        return "/"
    prefix = "/administrativeUnits/"
    if text.startswith(prefix):
        parsed = _uuid(text[len(prefix):])
        return f"{prefix}{parsed}" if parsed else "unknown"
    return "unknown"


def _retry_after(headers: dict[str, str]) -> int:
    try:
        return min(3600, max(1, int(str(headers.get("retry-after", "30")).strip())))
    except ValueError:
        return 30


def _arm_next_rejected(url: str, subscription: str) -> bool:
    from threatsight_api.connectors.microsoft.bounds import approved_url

    try:
        approved_url(url, "arm")
    except CollectionFailure:
        return True
    parsed = urlsplit(url)
    expected = f"/subscriptions/{subscription}/providers/Microsoft.Authorization/roleAssignments"
    return expected not in parsed.path or parse_qs(parsed.query).get("api-version") != [ROLE_API]
