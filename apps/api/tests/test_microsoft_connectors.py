from __future__ import annotations

import inspect
import json
import re
import uuid
from datetime import UTC, datetime

import pytest

from threatsight_api.connectors.microsoft import arg as arg_module
from threatsight_api.connectors.microsoft import entra as entra_module
from threatsight_api.connectors.microsoft import fixtures as fixture_module
from threatsight_api.connectors.microsoft.arg import QUERIES
from threatsight_api.connectors.microsoft.bounds import (
    MAX_RESPONSE_BYTES,
    CollectionFailure,
    approved_url,
    credential_refused,
    graph_next_rejected,
)
from threatsight_api.connectors.microsoft.dispatch import execute_claimed, run_collection
from threatsight_api.connectors.microsoft.entra import PRIVILEGED_AZURE_ROLES
from threatsight_api.connectors.microsoft.fixtures import (
    DANGLING,
    DECOY_ROLE,
    OWNER_ROLE,
    TENANT,
    FixtureTransport,
    azure_configuration,
    entra_configuration,
)
from threatsight_api.connectors.microsoft.live import resolve_credential
from threatsight_api.connectors.microsoft.registry import accepted_instance, accepted_job_input, parse_configuration
from threatsight_api.connectors.microsoft.transport import VendorRequest, VendorResponse, open_vendor
from threatsight_api.runner import interpret_control_plane

NOW = datetime(2026, 10, 30, tzinfo=UTC)
JOB_ID = "11111111-1111-4111-8111-111111111111"
TENANT_A = "22222222-2222-4222-8222-222222222222"
WORKSPACE_A = "33333333-3333-4333-8333-333333333333"


@pytest.fixture(autouse=True)
def _no_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(arg_module, "pause", lambda _seconds: None)
    monkeypatch.setattr(entra_module, "pause", lambda _seconds: None)


def _clock() -> datetime:
    return NOW


def _job(key: str, configuration: dict, *, mode: str = "fixture", job_type: str = "inventory", tenant: str = TENANT_A, workspace: str = WORKSPACE_A) -> dict:
    body = dict(configuration)
    body["mode"] = mode
    return {
        "id": JOB_ID,
        "idempotency_key": f"{key}-{job_type}",
        "job_type": job_type,
        "dispatch": {
            "connector_key": key,
            "mode": mode,
            "configuration": body,
            "secret_locator": "synthetic-locator",
            "tenant_id": tenant,
            "workspace_id": workspace,
        },
    }


def _run(key: str, fixture: str = "nordic-retail", **kwargs):
    configuration = azure_configuration(fixture) if key == "azure.resource_graph" else entra_configuration(fixture)
    return run_collection(
        _job(key, configuration),
        disabled=lambda: False,
        cancelled=lambda: False,
        lease_ok=lambda: True,
        clock=_clock,
        **kwargs,
    )


def _dump(envelope) -> str:
    return json.dumps(envelope.model_dump(mode="json"), sort_keys=True)


def test_queries_are_constant_and_pageable() -> None:
    assert len(QUERIES) == 4
    for query in QUERIES.values():
        assert query.startswith("// threatsight:")
        assert "| take" not in query.lower()
        assert "| limit" not in query.lower()
        assert "| sample" not in query.lower()
        assert "order by id asc" in query


def test_fixtures_contain_no_real_identifiers() -> None:
    source = inspect.getsource(fixture_module)
    assert re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", source) is None
    assert "bearer " not in source.lower()


def test_nordic_azure_collection_is_bounded_and_deterministic() -> None:
    first = _run("azure.resource_graph")
    second = _run("azure.resource_graph")
    assert first.maturity == "fixture_tested"
    assert first.mode == "fixture"
    assert first.content_hash == second.content_hash
    dumped = _dump(first)
    assert "live_verified" not in dumped
    assert "synthetic-should-drop" not in dumped
    assert "\r" not in dumped and "\nINFO" not in dumped
    kinds = {record.kind for record in first.records}
    assert {"subscription", "resource_group", "virtual_network", "subnet", "public_ip", "network_security_rule", "virtual_machine", "application_gateway", "collection_status"} <= kinds
    vm = next(record for record in first.records if record.external_id.endswith("/virtualMachines/vm-orders"))
    assert vm.attributes["name"] == "vm-orders INFO"
    assert vm.attributes["tags"]["service"] == "customer-ordering"
    assert "password" not in vm.attributes["tags"]
    addresses = [record.attributes.get("address") for record in first.records]
    assert "203.0.113.10" in addresses


def test_nordic_entra_keeps_only_correlation_fields() -> None:
    envelope = _run("entra.identity")
    dumped = _dump(envelope)
    for marker in ("synthetic-mailbox", "synthetic-sign-in", "synthetic-label", "synthetic-should-drop", "Global Administrator", "passwordCredentials", DECOY_ROLE):
        assert marker not in dumped
    assert envelope.maturity == "fixture_tested"
    privileged = next(record for record in envelope.records if record.external_id == "62e90394-69f5-4237-9190-012177145e10")
    unknown = next(record for record in envelope.records if record.external_id == "11111111-1111-4111-8111-111111111111")
    assert privileged.attributes["privileged"] is True
    assert unknown.attributes["privileged"] == "unknown"
    group_assignment = next(record for record in envelope.records if record.attributes.get("principal_id") == "22222222-2222-4222-8222-222222222222" and record.kind == "role_assignment")
    user_assignment = next(record for record in envelope.records if record.attributes.get("principal_id") == "33333333-3333-4333-8333-333333333333" and record.kind == "role_assignment")
    assert group_assignment.attributes["assignment_basis"] == "group"
    assert user_assignment.attributes["assignment_basis"] == "direct"
    membership = next(record for record in envelope.records if record.kind == "group_membership")
    assert membership.attributes["relationship"] == "transitive"
    deleted = next(record for record in envelope.records if record.external_id == "55555555-5555-4555-8555-555555555555")
    assert deleted.truth_state == "unknown"
    azure = next(record for record in envelope.records if record.kind == "azure_role_assignment")
    assert azure.attributes["role_definition_id"] == OWNER_ROLE
    assert OWNER_ROLE in PRIVILEGED_AZURE_ROLES


@pytest.mark.parametrize("connector", ["azure.resource_graph", "entra.identity"])
@pytest.mark.parametrize(
    ("fixture", "expectation"),
    [
        ("empty", "empty"),
        ("forbidden", "denied"),
        ("throttled", "throttled"),
        ("transient", "ok"),
        ("malformed", "malformed"),
        ("oversized", "oversized"),
        ("excessive", "capped"),
        ("duplicates", "duplicate"),
        ("dangling", "dangling"),
        ("conflicting", "conflicting"),
        ("partial", "partial"),
        ("missing-optional", "optional"),
    ],
)
def test_fixture_matrix(connector: str, fixture: str, expectation: str) -> None:
    transport = FixtureTransport(fixture)
    configuration = azure_configuration(fixture) if connector == "azure.resource_graph" else entra_configuration(fixture)
    job = _job(connector, configuration)
    gates = {"disabled": False, "cancelled": False, "lease": True}

    def invoke():
        return run_collection(
            job,
            disabled=lambda: gates["disabled"],
            cancelled=lambda: gates["cancelled"],
            lease_ok=lambda: gates["lease"],
            clock=_clock,
            transport=transport,
            max_pages=3 if expectation == "capped" else 10,
        )

    if expectation == "denied":
        with pytest.raises(CollectionFailure) as caught:
            invoke()
        assert caught.value.code == "permission_denied"
        return
    if expectation in {"malformed", "oversized"}:
        with pytest.raises(CollectionFailure) as caught:
            invoke()
        assert caught.value.code == ("malformed_response" if expectation == "malformed" else "response_too_large")
        return
    envelope = invoke()
    dumped = _dump(envelope)
    assert envelope.maturity == "fixture_tested"
    assert "live_verified" not in dumped
    if expectation == "empty":
        assert {record.kind for record in envelope.records} == {"collection_status"}
    elif expectation == "throttled":
        status = next(record for record in envelope.records if record.kind == "collection_status")
        assert status.attributes["retry_after_seconds"] == 2
        assert "rate_limited" in status.limitations
        assert len(transport.calls) == 1
    elif expectation == "ok":
        assert any(len([call for call in transport.calls if call.url == transport.calls[0].url]) >= 3 for _ in [0])
    elif expectation == "capped":
        assert len(transport.calls) == 3
        assert any("page_limit" in record.limitations for record in envelope.records)
    elif expectation == "duplicate":
        assert any("duplicate_collapsed" in record.limitations for record in envelope.records)
    elif expectation == "dangling":
        if connector == "azure.resource_graph":
            assert any("dangling_reference" in record.limitations for record in envelope.records)
            assert DANGLING not in {record.external_id for record in envelope.records}
        else:
            assert any(record.truth_state == "unknown" for record in envelope.records)
    elif expectation == "conflicting":
        assert any(record.truth_state == "conflicting" for record in envelope.records)
    elif expectation == "partial" and connector == "azure.resource_graph":
        assert any("truncated_result" in record.limitations for record in envelope.records)
    elif expectation == "optional" and connector == "entra.identity":
        status = next(record for record in envelope.records if record.kind == "collection_status")
        assert "privileged_eligibility_unsupported" in status.limitations
        assert "azure_role_assignments_unsupported" in status.limitations
        assert any(record.kind == "role_assignment" for record in envelope.records)
        assert not any(record.kind == "group_membership" for record in envelope.records)


def test_cancellation_kill_switch_and_stale_lease_stop_pagination() -> None:
    for gate, code in (("cancelled", "cancelled"), ("disabled", "kill_switch")):
        transport = FixtureTransport("nordic-retail")
        original = transport.send_once

        def send_once(request, token, original=original):
            result = original(request, token)
            if gate == "cancelled":
                flags["cancelled"] = True
            else:
                flags["disabled"] = True
            return result

        flags = {"cancelled": False, "disabled": False}
        transport.send_once = send_once  # type: ignore[method-assign]
        result = execute_claimed(
            _job("azure.resource_graph", azure_configuration()),
            TENANT_A,
            WORKSPACE_A,
            disabled=lambda: flags["disabled"],
            cancelled=lambda: flags["cancelled"],
            lease_ok=lambda: True,
            clock=_clock,
            transport=transport,
        )
        assert result["action"] == "fail"
        assert result["code"] == code
        assert len(transport.calls) == 1
        assert "203.0.113.10" not in result["detail"]

    transport = FixtureTransport("nordic-retail")
    original = transport.send_once
    flags = {"ok": True}

    def send_once(request, token, original=original):
        flags["ok"] = False
        return original(request, token)

    transport.send_once = send_once  # type: ignore[method-assign]
    result = execute_claimed(
        _job("azure.resource_graph", azure_configuration()),
        TENANT_A,
        WORKSPACE_A,
        disabled=lambda: False,
        cancelled=lambda: False,
        lease_ok=lambda: flags["ok"],
        clock=_clock,
        transport=transport,
    )
    assert result == {"action": "stop"}
    assert len(transport.calls) == 1


def test_cross_tenant_rejection_does_not_call_vendor() -> None:
    transport = FixtureTransport("nordic-retail")
    result = execute_claimed(
        _job("entra.identity", entra_configuration()),
        "other-tenant",
        WORKSPACE_A,
        disabled=lambda: False,
        cancelled=lambda: False,
        lease_ok=lambda: True,
        transport=transport,
    )
    assert result["code"] == "tenant_mismatch"
    assert transport.calls == []


def test_configuration_rejects_client_queries_urls_and_live_labels() -> None:
    marker = "marker-query-value"
    with pytest.raises(ValueError) as caught:
        parse_configuration("azure.resource_graph", "fixture", {**azure_configuration(), "query": marker})
    assert marker not in str(caught.value)
    with pytest.raises(ValueError):
        parse_configuration("entra.identity", "fixture", {**entra_configuration(), "endpoint": "https://evil.example/collect"})
    with pytest.raises(ValueError):
        accepted_instance(
            connector_key="azure.resource_graph", mode="fixture", maturity="live_verified",
            configuration=azure_configuration(), runner_id=uuid.uuid4(), secret_reference_id=None,
        )
    with pytest.raises(ValueError):
        accepted_instance(
            connector_key="entra.identity", mode="live", maturity="experimental",
            configuration={"microsoft_tenant_id": TENANT, "subscription_ids": []},
            runner_id=uuid.uuid4(), secret_reference_id=None,
        )
    maturity, parsed = accepted_instance(
        connector_key="azure.resource_graph", mode="fixture", maturity="unsupported",
        configuration=azure_configuration(), runner_id=uuid.uuid4(), secret_reference_id=None,
    )
    assert maturity == "fixture_tested"
    assert "query" not in parsed
    with pytest.raises(ValueError):
        accepted_job_input("entra.identity", {"query": marker})


def test_continuation_and_destinations_are_allow_listed() -> None:
    for url in (
        "http://169.254.169.254/metadata/instance",
        "https://169.254.169.254/metadata",
        "https://graph.microsoft.com.evil.example/v1.0/users",
        "https://user:pass@graph.microsoft.com/v1.0/users",
        "https://graph.microsoft.com/v1.0/users#fragment",
        "file:///tmp/collector",
    ):
        with pytest.raises(CollectionFailure):
            approved_url(url, "graph" if "graph" in url else "arm")
    assert graph_next_rejected("https://graph.microsoft.com/v1.0/users?$select=mail", frozenset({"id"}))
    assert graph_next_rejected("https://evil.example/v1.0/roleManagement/directory/roleDefinitions?$select=id", frozenset({"id"}))
    approved_url("https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id", "graph")
    approved_url(f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token", "login")


def test_redirect_and_oversized_vendor_payloads_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Opener:
        def open(self, request, timeout=0):  # noqa: ANN001
            raise ValueError("redirect refused")

    monkeypatch.setattr("threatsight_api.connectors.microsoft.transport.urllib.request.build_opener", lambda *_args: Opener())
    with pytest.raises(CollectionFailure) as redirected:
        open_vendor("GET", "https://graph.microsoft.com/v1.0/users", None, {})
    assert redirected.value.code == "redirect_refused"

    class Body:
        status = 200
        headers: dict[str, str] = {}

        def read(self, _count: int) -> bytes:
            return b"{" + b"x" * MAX_RESPONSE_BYTES

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> bool:
            return False

    class Large:
        def open(self, request, timeout=0):  # noqa: ANN001
            return Body()

    monkeypatch.setattr("threatsight_api.connectors.microsoft.transport.urllib.request.build_opener", lambda *_args: Large())
    with pytest.raises(CollectionFailure) as oversized:
        open_vendor("GET", "https://management.azure.com/subscriptions", None, {})
    assert oversized.value.code == "response_too_large"


def test_live_collection_is_opt_in_and_redacts_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "synthetic-client-secret-value"
    token = "synthetic-access-token-value"
    calls: list[VendorRequest] = []

    class Scripted:
        def authorize(self, tenant: str, client_id: str, client_secret: str, scope: str) -> str:
            assert client_secret == secret
            assert scope == "https://management.azure.com/.default"
            return token

        def send_once(self, request: VendorRequest, presented: str) -> VendorResponse:
            assert presented == token
            calls.append(request)
            return VendorResponse(200, {}, {"data": [], "count": 0, "totalRecords": 0, "resultTruncated": False})

    scripted = Scripted()
    with pytest.raises(CollectionFailure) as disabled:
        run_collection(
            _job("azure.resource_graph", {"microsoft_tenant_id": TENANT, "subscription_ids": [azure_configuration()["subscription_ids"][0]]}, mode="live"),
            disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True, clock=_clock, transport=scripted,
        )
    assert disabled.value.code == "live_disabled"
    assert calls == []

    monkeypatch.setenv("THREATSIGHT_MICROSOFT_LIVE", "true")
    monkeypatch.setenv("THREATSIGHT_MICROSOFT_CREDENTIALS", json.dumps({
        "synthetic-locator": {"client_id": TENANT, "client_secret": "placeholder-credential-value"},
    }))
    with pytest.raises(CollectionFailure) as refused:
        resolve_credential("synthetic-locator")
    assert refused.value.code == "secret_refused"
    assert "placeholder" not in str(refused.value)
    assert credential_refused("placeholder-credential-value")

    monkeypatch.setenv("THREATSIGHT_MICROSOFT_CREDENTIALS", json.dumps({
        "synthetic-locator": {"client_id": TENANT, "client_secret": secret},
    }))
    envelope = run_collection(
        _job("azure.resource_graph", {"microsoft_tenant_id": TENANT, "subscription_ids": [azure_configuration()["subscription_ids"][0]]}, mode="live"),
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True, clock=_clock, transport=scripted,
    )
    dumped = _dump(envelope)
    assert envelope.maturity == "live_verified"
    assert secret not in dumped and token not in dumped
    assert calls and all(call.url.startswith("https://management.azure.com/") for call in calls)
    assert all(call.json_body and call.json_body["query"] in set(QUERIES.values()) for call in calls)


def test_scope_and_principal_references_cannot_leave_the_allow_list() -> None:
    second = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    calls: list[str] = []

    class Scripted:
        def send_once(self, request: VendorRequest, token: str) -> VendorResponse:
            calls.append(request.url)
            if "roleManagement/directory/roleAssignments?" in request.url:
                return VendorResponse(200, {}, {"value": [{
                    "id": "66666666-6666-4666-8666-666666666666",
                    "principalId": "../evil",
                    "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
                    "directoryScopeId": "https://evil.example/scope",
                }]})
            return VendorResponse(200, {}, {"value": []})

    configuration = entra_configuration()
    configuration["subscription_ids"] = [configuration["subscription_ids"][0], second]
    envelope = run_collection(
        _job("entra.identity", configuration),
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True, clock=_clock,
        transport=Scripted(),
    )
    assert all("evil" not in call and ".." not in call for call in calls)
    assert any(configuration["subscription_ids"][0] in call for call in calls)
    assert any(second in call for call in calls)
    assert "https://evil.example/scope" not in _dump(envelope)
    assert not any(record.kind == "role_assignment" for record in envelope.records)


def test_control_plane_status_does_not_follow_ambiguous_failures() -> None:
    assert interpret_control_plane(200, {}) == "ok"
    assert interpret_control_plane(409, {"detail": "Job cancellation requested"}) == "cancelled"
    assert interpret_control_plane(409, {"detail": "Job lease has expired"}) == "lease_lost"
    assert interpret_control_plane(503, {"detail": "Connector execution is disabled"}) == "kill_switch"
