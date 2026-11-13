"""Run one claimed job through a registered read-only connector."""

from __future__ import annotations

from datetime import UTC, datetime

from threatsight_api.connectors.microsoft.bounds import MAX_PAGES, MAX_RECORDS, CollectionFailure, Interrupted
from threatsight_api.connectors.microsoft.live import ARM_SCOPE, GRAPH_SCOPE, live_enabled, resolve_credential
from threatsight_api.connectors.microsoft.registry import CUSTOMER_RESIDENT, build_connector
from threatsight_api.connectors.sdk import Capability, CollectionEnvelope, ConnectorMode, NormalizedRecord, PageRequest

DETAILS = {
    "kill_switch": "Execution disabled during collection",
    "cancelled": "Collection cancelled",
    "permission_denied": "Required read permission is not available",
    "tenant_mismatch": "Runner tenant does not match the job",
    "live_disabled": "Live collection is disabled",
    "secret_unavailable": "Secret reference could not be resolved",
    "secret_refused": "Live credential was refused",
    "unsupported_connector": "No adapter is registered for this connector",
    "malformed_response": "Vendor response was not usable",
    "response_too_large": "Vendor response exceeded the size limit",
    "transient_failure": "Vendor request failed temporarily",
    "destination_refused": "Vendor destination was refused",
    "redirect_refused": "Vendor redirect was refused",
    "query_rejected": "Collection query was rejected",
    "token_request_failed": "Token request failed",
    "vendor_unavailable": "Vendor endpoint was unavailable",
    "collection_failed": "Collection stopped",
    "rate_limited": "Vendor rate limit stopped the collection",
    "request_too_large": "Collection request was too large",
    "authentication_rejected": "Device authentication was rejected",
    "host_key_required": "Pinned host key is required",
    "host_key_mismatch": "SSH host key did not match",
    "connection_timeout": "Device connection timed out",
    "connection_failed": "Device connection failed",
    "malformed_xml": "Device response was not usable",
    "malicious_namespace": "Device response namespace was rejected",
    "xml_depth_exceeded": "Device response nesting was rejected",
    "xml_node_limit": "Device response size was rejected",
    "rpc_rejected": "Collection operation was rejected",
    "live_transport_unavailable": "Live NETCONF transport is not available",
    "ssh_algorithm_rejected": "SSH algorithm was rejected",
    "dns_rebinding": "Device address was not stable",
    "dns_resolution_unavailable": "Device name resolution is not available",
    "session_limit": "Collection session exceeded its time limit",
    "minimization_rejected": "Collection result was rejected",
}
RETRYABLE = frozenset({"kill_switch", "transient_failure", "vendor_unavailable", "rate_limited", "token_request_failed"})


def execute_claimed(job: dict, runner_tenant_id: str, runner_workspace_id: str, *, disabled, cancelled, lease_ok, clock=None, transport=None, max_pages: int = MAX_PAGES) -> dict:
    try:
        dispatch = job.get("dispatch") if isinstance(job.get("dispatch"), dict) else {}
        if str(dispatch.get("tenant_id")) != str(runner_tenant_id) or str(dispatch.get("workspace_id")) != str(runner_workspace_id):
            return _failure("tenant_mismatch")
        if dispatch.get("connector_key") not in CUSTOMER_RESIDENT:
            return _failure("unsupported_connector")
        if disabled():
            return _failure("kill_switch", True)
        gate = _gate(cancelled, lease_ok)
        if gate:
            return _failure(gate) if gate == "cancelled" else {"action": "stop"}
        envelope = run_collection(job, disabled=disabled, cancelled=cancelled, lease_ok=lease_ok, clock=clock, transport=transport, max_pages=max_pages)
        return {"action": "complete", "envelope": envelope.model_dump(mode="json")}
    except Interrupted as exc:
        if exc.code == "lease_lost":
            return {"action": "stop"}
        return _failure(exc.code, exc.code == "kill_switch")
    except CollectionFailure as exc:
        return _failure(exc.code, exc.retryable)
    except Exception:
        return _failure("collection_failed")


def run_collection(job: dict, *, disabled, cancelled, lease_ok, clock=None, transport=None, max_pages: int = MAX_PAGES) -> CollectionEnvelope:
    dispatch = job["dispatch"]
    configuration = dict(dispatch.get("configuration") or {})
    mode = str(dispatch.get("mode") or configuration.get("mode") or "fixture")
    configuration["mode"] = mode
    graph_token = ""
    arm_token = ""
    api_key = ""
    if mode == "live" and dispatch["connector_key"] == "meraki.dashboard":
        from threatsight_api.connectors.meraki.live import live_enabled as meraki_live_enabled
        from threatsight_api.connectors.meraki.live import resolve_api_key

        if not meraki_live_enabled():
            raise CollectionFailure("live_disabled")
        api_key = resolve_api_key(str(dispatch.get("secret_locator") or ""))
    elif mode == "live" and dispatch["connector_key"] == "junos.device":
        from threatsight_api.connectors.junos.live import live_enabled as junos_live_enabled
        from threatsight_api.connectors.junos.live import open_session
        from threatsight_api.connectors.junos.live import resolve_credential as resolve_junos_credential

        if not junos_live_enabled():
            raise CollectionFailure("live_disabled")
        resolve_junos_credential(str(dispatch.get("secret_locator") or ""))
        open_session(configuration)
    elif mode == "live":
        if not live_enabled():
            raise CollectionFailure("live_disabled")
        client_id, secret = resolve_credential(str(dispatch.get("secret_locator") or ""))
        if transport is None:
            from threatsight_api.connectors.microsoft.transport import LiveTransport
            transport = LiveTransport()
        tenant = str(configuration["microsoft_tenant_id"])
        if dispatch["connector_key"] == "azure.resource_graph":
            arm_token = transport.authorize(tenant, client_id, secret, ARM_SCOPE)
        else:
            graph_token = transport.authorize(tenant, client_id, secret, GRAPH_SCOPE)
            if configuration.get("subscription_ids"):
                arm_token = transport.authorize(tenant, client_id, secret, ARM_SCOPE)
    connector = build_connector(dispatch["connector_key"], configuration, transport, clock, graph_token, arm_token, api_key)
    if connector is None:
        raise CollectionFailure("unsupported_connector")

    def guard() -> None:
        if disabled():
            raise Interrupted("kill_switch")
        state = "cancelled" if cancelled() else None
        if state is None and not lease_ok():
            state = "lease_lost"
        if state:
            raise Interrupted(state)

    connector.guard = guard
    now = clock() if clock else datetime.now(UTC)
    if job.get("job_type") == "health":
        guard()
        health = connector.health()
        records = [_status(job, connector, [health.state], False, 0, now, {"state": health.state})]
        return _envelope(job, connector, records, now)
    if job.get("job_type") != "inventory":
        records = [_status(job, connector, ["capability_unsupported"], True, 0, now, {}, truth="unsupported")]
        return _envelope(job, connector, records, now)

    records: list[NormalizedRecord] = []
    cursor = None
    pages = 0
    partial = False
    retry_after = None
    try:
        while pages < max_pages and len(records) < MAX_RECORDS:
            guard()
            page = connector.collect(Capability.INVENTORY, PageRequest(cursor=cursor, limit=100))
            pages += 1
            if page.unsupported and not records and not page.records:
                raise CollectionFailure("permission_denied")
            records.extend(page.records)
            if page.retry_after_seconds:
                retry_after = page.retry_after_seconds
                connector.notes.append("rate_limited")
            if page.partial or page.retry_after_seconds or page.unsupported:
                partial = True
                break
            cursor = page.next_cursor
            if not cursor:
                break
        else:
            partial = True
            connector.notes.append("page_limit")
    except Interrupted as exc:
        if dispatch["connector_key"] not in {"meraki.dashboard", "junos.device"} or exc.code == "lease_lost" or not records:
            raise
        partial = True
        connector.notes.append(exc.code)
    if len(records) > MAX_RECORDS - 1:
        records = records[: MAX_RECORDS - 1]
        partial = True
        connector.notes.append("record_limit")
    collapsed, notes = _collapse(records)
    _mark_dangling(collapsed)
    if partial or notes or connector.notes:
        partial = partial or bool(notes)
    maturity_blocked = partial or any(note in connector.notes for note in {
        "rate_limited", "page_limit", "record_limit", "continuation_rejected", "truncated_result", "malformed_row",
    })
    for record in collapsed:
        if mode != "live" and record.truth_state == "live_verified":
            record.truth_state = "fixture_tested"
        elif mode == "live" and maturity_blocked and record.truth_state == "live_verified":
            record.truth_state = "partial"
    status_attributes = {"retry_after_seconds": retry_after} if retry_after else {}
    collapsed.append(_status(job, connector, list(dict.fromkeys([*connector.notes, *notes])), partial, pages, now, status_attributes))
    collapsed.sort(key=lambda item: (item.kind, item.external_id))
    live_result = mode == "live" and not maturity_blocked and dispatch["connector_key"] != "junos.device"
    return _envelope(job, connector, collapsed, now, allow_live=live_result)


def _gate(cancelled, lease_ok) -> str | None:
    if cancelled():
        return "cancelled"
    if not lease_ok():
        return "lease_lost"
    return None


def _collapse(records: list[NormalizedRecord]) -> tuple[list[NormalizedRecord], list[str]]:
    kept: dict[str, NormalizedRecord] = {}
    notes: list[str] = []
    for record in records:
        previous = kept.get(record.external_id)
        if previous is None:
            kept[record.external_id] = record
            continue
        if previous.model_dump(mode="json") != record.model_dump(mode="json"):
            previous.truth_state = "conflicting"
            _limit(previous, "conflicting_source_row")
            notes.append("conflicting_source_row")
        else:
            notes.append("duplicate_collapsed")
    return list(kept.values()), notes


def _mark_dangling(records: list[NormalizedRecord]) -> None:
    identities = {record.external_id for record in records}
    for record in records:
        target = record.attributes.get("associated_resource_id")
        if target and target not in identities:
            record.attributes["association_state"] = "unknown"
            _limit(record, "dangling_reference")


def _status(job, connector, notes, partial, pages, now, attributes=None, truth=None) -> NormalizedRecord:
    state = truth or ("partial" if partial else "fixture_tested" if connector.mode == ConnectorMode.FIXTURE else "unknown")
    body = {"pages": pages, "partial": partial, **(attributes or {})}
    return NormalizedRecord(
        kind="collection_status",
        external_id=f"collection:{job['id']}",
        collected_at=now,
        truth_state=state,
        attributes=body,
        provenance={"source": connector.connector_key, "mode": connector.mode.value, "contract": "collection.v1"},
        limitations=list(dict.fromkeys(notes))[:40],
    )


def _envelope(job, connector, records, now, allow_live: bool = False) -> CollectionEnvelope:
    maturity = connector.maturity if allow_live else (
        connector.maturity if connector.mode == ConnectorMode.FIXTURE else "experimental"
    )
    if connector.mode == ConnectorMode.FIXTURE:
        maturity = "fixture_tested"
    return CollectionEnvelope(
        connector_key=connector.connector_key,
        job_id=str(job["id"]),
        idempotency_key=str(job["idempotency_key"]),
        sequence=0,
        mode=connector.mode,
        maturity=maturity,
        records=records,
        emitted_at=now,
        content_hash=CollectionEnvelope.hash_records(records),
    )


def _limit(record: NormalizedRecord, value: str) -> None:
    if value not in record.limitations and len(record.limitations) < 40:
        record.limitations.append(value)


def _failure(code: str, retryable: bool = False) -> dict:
    safe = code if code in DETAILS else "collection_failed"
    return {"action": "fail", "code": safe, "detail": DETAILS[safe], "retryable": bool(retryable) and safe in RETRYABLE}
