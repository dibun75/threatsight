from __future__ import annotations

import inspect
import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

from threatsight_api.api import connectors as connectors_api
from threatsight_api.connectors.junos import device as device_module
from threatsight_api.connectors.junos.bounds import (
    CONNECT_TIMEOUT_SECONDS,
    DNS_TIMEOUT_SECONDS,
    MAX_CONNECT_ATTEMPTS,
    MAX_ROUTES,
    READ_TIMEOUT_SECONDS,
    SESSION_SECONDS,
    CollectionFailure,
)
from threatsight_api.connectors.junos.fixtures import DEVICE, OTHER, PIN, FixtureTransport, configuration, document
from threatsight_api.connectors.junos.live import live_enabled, open_session, resolve_credential
from threatsight_api.connectors.junos.rpc import ALLOWED, PROHIBITED, render
from threatsight_api.connectors.junos.target import (
    accept_algorithm,
    approved_endpoint,
    approved_port,
    default_resolver,
    host_key_accepted,
    ignored_proxy_environment,
    pin_address,
)
from threatsight_api.connectors.junos.xmlsec import parse_document
from threatsight_api.connectors.microsoft.dispatch import execute_claimed, run_collection
from threatsight_api.connectors.sdk import Capability, PageRequest
from threatsight_api.connectors.microsoft.registry import accepted_instance, accepted_job_input, build_connector, parse_configuration

NOW = datetime(2026, 10, 30, tzinfo=UTC)
TENANT_A = "22222222-2222-4222-8222-222222222222"
WORKSPACE_A = "33333333-3333-4333-8333-333333333333"
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + ("A" * 80) + "\n-----END OPENSSH PRIVATE KEY-----\n"
LEAKS = (
    "secret-shaped-value", "hash-shaped-value", "public-shaped", "radius-shaped", "operator-shaped",
    "IGNORE-THIS-TEXT", "comment-shaped-secret", "unrelated-object", "198.51.100.0/24",
    "BEGIN CERTIFICATE", "scheme=file", "<rpc-reply", "<!DOCTYPE", "pre-shared-key", "PRIVATE KEY",
)


def _job(body: dict, *, mode: str = "fixture", tenant: str = TENANT_A, workspace: str = WORKSPACE_A) -> dict:
    payload = dict(body)
    payload["mode"] = mode
    return {
        "id": "11111111-1111-4111-8111-111111111111",
        "idempotency_key": "junos-inventory",
        "job_type": "inventory",
        "dispatch": {
            "connector_key": "junos.device",
            "mode": mode,
            "configuration": payload,
            "secret_locator": "synthetic-locator",
            "tenant_id": tenant,
            "workspace_id": workspace,
        },
    }


def _run(fixture: str = "nordic-retail", **kwargs):
    fingerprint = None if fixture == "missing-host-key" else PIN
    return run_collection(
        _job(configuration(fixture, fingerprint=fingerprint)),
        disabled=lambda: False,
        cancelled=lambda: False,
        lease_ok=lambda: True,
        clock=lambda: NOW,
        **kwargs,
    )


def _dump(envelope) -> str:
    return json.dumps(envelope.model_dump(mode="json"), sort_keys=True)


def _status(envelope):
    return next(record for record in envelope.records if record.kind == "collection_status")


def _kinds(envelope) -> dict[str, list]:
    grouped: dict[str, list] = {}
    for record in envelope.records:
        grouped.setdefault(record.kind, []).append(record)
    return grouped


def _fail(fixture: str) -> dict:
    return execute_claimed(
        _job(configuration(fixture, fingerprint=None if fixture == "missing-host-key" else PIN)),
        TENANT_A, WORKSPACE_A,
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True, clock=lambda: NOW,
    )


def test_collection_is_deterministic_minimized_and_fixture_tested() -> None:
    first = _run()
    second = _run()
    dumped = _dump(first)
    kinds = _kinds(first)
    assert first.maturity == "fixture_tested"
    assert first.content_hash == second.content_hash
    assert kinds["capability"][0].attributes == {"base_1_0": True, "base_1_1": True, "junos_1_0": True}
    device = kinds["device"][0]
    assert device.attributes["device_id"] == DEVICE
    assert device.attributes["model"] == "SRX-SYN"
    assert device.attributes["chassis_id"] == "SYNTHCHASSIS0001"
    assert device.attributes["junos_version"] == "23.4R1-synthetic"
    assert device.attributes["informational_hostname"] == "synth-edge"
    assert "hostname_is_not_authority" in device.limitations
    logical = {item.attributes["name"]: item for item in kinds["interface"]}
    assert logical["ge-0/0/0.0"].attributes["zone"] == "untrust"
    assert logical["ge-0/0/0.0"].attributes["management"] is False
    assert logical["fxp0.0"].attributes["management"] is True
    assert logical["fxp0.0"].attributes["zone"] == "management"
    assert "management" not in logical["fxp0"].attributes
    assert {item.attributes["destination_prefix"] for item in kinds["route"]} == {"0.0.0.0/0", "10.9.0.0/24"}
    actions = {item.attributes["name"]: item.attributes["action"] for item in kinds["security_policy"]}
    assert actions == {"branch-egress": "allow", "edge-deny": "deny"}
    vpn = kinds["vpn_gateway"][0]
    assert vpn.attributes["peer"] == "203.0.113.20"
    assert vpn.attributes["operational_state"] == "up"
    assert vpn.attributes["bind_interface"] == "st0.0"
    ssh = next(item for item in kinds["management_service"] if item.attributes["service"] == "ssh")
    assert ssh.attributes["allowed_zones"] == ["management"]
    assert ssh.attributes["reachability"] == "not_observed"
    assert "configuration_is_not_reachability" in ssh.limitations
    http = next(item for item in kinds["management_service"] if item.attributes["service"] == "http")
    assert "source_context_unknown" in http.limitations
    assert all(record.truth_state != "live_verified" for record in first.records)
    for forbidden in LEAKS:
        assert forbidden not in dumped
    assert "\n" not in dumped


def test_partial_stale_conflicting_and_unknown_states() -> None:
    stale = _kinds(_run("stale"))
    assert stale["device"][0].truth_state == "stale"
    assert any(item.truth_state == "stale" for item in stale["interface"])
    conflicting = _kinds(_run("conflicting"))
    edge = next(item for item in conflicting["interface"] if item.attributes["name"] == "ge-0/0/0")
    assert edge.truth_state == "conflicting"
    assert "configured_operational_conflict" in edge.limitations
    dangling = _run("dangling")
    zone = next(item for item in dangling.records if item.kind == "security_zone" and item.attributes["name"] == "management")
    assert zone.attributes["association_state"] == "unknown"
    assert "ge-0/0/9.0" in zone.attributes["member_interfaces"]
    assert "dangling_reference" in zone.limitations
    partial = _run("partial")
    assert _status(partial).attributes["partial"] is True
    assert partial.maturity == "fixture_tested"
    assert "vendor_unavailable" in _status(partial).limitations
    assert any(record.kind == "interface" for record in partial.records)
    injected = _dump(_run("log-injection"))
    assert "INJECTED" not in injected
    assert "\n" not in injected


def test_route_bound_duplicates_and_invalid_prefixes() -> None:
    bounded = _run("full-table")
    routes = [item for item in bounded.records if item.kind == "route"]
    assert len(routes) == MAX_ROUTES
    assert _status(bounded).attributes["partial"] is True
    assert "route_limit" in _status(bounded).limitations
    assert bounded.maturity == "fixture_tested"
    duplicated = _run("duplicate")
    assert "duplicate_collapsed" in _status(duplicated).limitations
    assert len([item for item in duplicated.records if item.attributes.get("name") == "ge-0/0/0"]) == 1
    invalid = _dump(_run("invalid-prefix"))
    assert "999.1.1.1" not in invalid
    assert "10.8.0.1/24" not in invalid
    assert "invalid_prefix" in invalid
    unsupported = _kinds(_run("unsupported"))
    assert unsupported["device"][0].truth_state == "unsupported"
    assert "capability" not in unsupported


@pytest.mark.parametrize("fixture,code", [
    ("malformed", "malformed_xml"),
    ("xxe", "malformed_xml"),
    ("entities", "malformed_xml"),
    ("oversized", "response_too_large"),
    ("deep", "xml_depth_exceeded"),
    ("wide", "xml_node_limit"),
    ("malicious-namespace", "malicious_namespace"),
    ("host-key-mismatch", "host_key_mismatch"),
    ("missing-host-key", "host_key_required"),
    ("auth-rejected", "authentication_rejected"),
    ("timeout", "connection_timeout"),
])
def test_fail_closed_codes_are_redacted(fixture: str, code: str) -> None:
    result = _fail(fixture)
    encoded = json.dumps(result)
    assert result["code"] == code
    assert result["action"] == "fail"
    for forbidden in ("passwd", "evil.example", PIN, "synth-edge", "<", "PRIVATE KEY"):
        assert forbidden not in encoded


def test_parser_rejects_hostile_xml_without_echoing_it() -> None:
    samples = {
        "xxe": document("xxe", "hello"),
        "entities": document("entities", "hello"),
        "deep": document("deep", "hello"),
        "wide": document("wide", "hello"),
        "malicious-namespace": document("malicious-namespace", "hello"),
    }
    expected = {
        "xxe": "malformed_xml",
        "entities": "malformed_xml",
        "deep": "xml_depth_exceeded",
        "wide": "xml_node_limit",
        "malicious-namespace": "malicious_namespace",
    }
    for name, payload in samples.items():
        with pytest.raises(CollectionFailure) as caught:
            parse_document(payload)
        assert caught.value.code == expected[name]
        assert str(caught.value) == expected[name]
        assert payload.decode(errors="ignore") not in str(caught.value)


def test_reconnect_is_bounded_and_authentication_is_not_retried() -> None:
    timeout = FixtureTransport("timeout")
    _fail_transport = execute_claimed(
        _job(configuration("timeout")), TENANT_A, WORKSPACE_A,
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True,
        clock=lambda: NOW, transport=timeout,
    )
    assert _fail_transport["code"] == "connection_timeout"
    assert timeout.starts == MAX_CONNECT_ATTEMPTS
    assert timeout.reconnect_delays == [0.25, 0.5]
    assert all(delay <= 1 for delay in timeout.reconnect_delays)
    reconnect = FixtureTransport("reconnect")
    envelope = run_collection(
        _job(configuration("reconnect")),
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True,
        clock=lambda: NOW, transport=reconnect,
    )
    assert reconnect.starts == 2
    assert envelope.maturity == "fixture_tested"
    auth = FixtureTransport("auth-rejected")
    rejected = execute_claimed(
        _job(configuration("auth-rejected")), TENANT_A, WORKSPACE_A,
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True,
        clock=lambda: NOW, transport=auth,
    )
    assert rejected["code"] == "authentication_rejected"
    assert auth.starts == 1
    assert "authentication_rejected" == str(CollectionFailure("authentication_rejected"))


@pytest.mark.parametrize("operation", PROHIBITED)
def test_prohibited_operations_fail_closed(operation: str) -> None:
    from threatsight_api.connectors.junos.rpc import assert_allowed

    with pytest.raises(CollectionFailure) as caught:
        assert_allowed(operation)
    assert caught.value.code == "rpc_rejected"
    with pytest.raises(CollectionFailure):
        FixtureTransport("nordic-retail").rpc(operation)


def test_rendered_requests_stay_on_the_allowlist() -> None:
    for operation in sorted(ALLOWED):
        body = render(operation)
        assert b"<edit-config" not in body
        assert b"<commit" not in body
        assert b"pre-shared-key" not in body
        assert b"<cli" not in body
    interfaces = render("get-config-interfaces")
    assert b"<interfaces" in interfaces
    assert b"<security" not in interfaces
    assert b"xpath" not in interfaces.lower()


def test_cancellation_kill_switch_and_lease_loss() -> None:
    for gate, limitation in (("cancelled", "cancelled"), ("disabled", "kill_switch")):
        transport = FixtureTransport("nordic-retail")
        flags = {"cancelled": False, "disabled": False}
        original = transport.rpc

        def rpc(operation, original=original, gate=gate):
            result = original(operation)
            flags[gate] = True
            return result

        transport.rpc = rpc
        envelope = run_collection(
            _job(configuration()),
            disabled=lambda: flags["disabled"],
            cancelled=lambda: flags["cancelled"],
            lease_ok=lambda: True,
            clock=lambda: NOW,
            transport=transport,
        )
        assert envelope.maturity == "fixture_tested"
        assert _status(envelope).attributes["partial"] is True
        assert limitation in _status(envelope).limitations
        assert transport.calls == ["hello"]

    transport = FixtureTransport("nordic-retail")
    original = transport.rpc
    flags = {"ok": True}

    def expire(operation, original=original):
        result = original(operation)
        flags["ok"] = False
        return result

    transport.rpc = expire
    result = execute_claimed(
        _job(configuration()), TENANT_A, WORKSPACE_A,
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: flags["ok"],
        clock=lambda: NOW, transport=transport,
    )
    assert result == {"action": "stop"}
    assert transport.calls == ["hello"]


def test_cross_tenant_and_workspace_never_call_the_device() -> None:
    for tenant, workspace in (("other-tenant", WORKSPACE_A), (TENANT_A, "other-workspace")):
        transport = FixtureTransport("nordic-retail")
        result = execute_claimed(
            _job(configuration()), tenant, workspace,
            disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True,
            clock=lambda: NOW, transport=transport,
        )
        assert result["code"] == "tenant_mismatch"
        assert transport.calls == []
        assert transport.starts == 0


def test_registration_rejects_scope_escapes() -> None:
    with pytest.raises(ValueError, match="customer runner"):
        accepted_instance(
            connector_key="junos.device", mode="fixture", maturity="experimental",
            configuration=configuration(), runner_id=None, secret_reference_id=None,
        )
    with pytest.raises(ValueError, match="secret reference"):
        accepted_instance(
            connector_key="junos.device", mode="live", maturity="experimental",
            configuration=_live_configuration(), runner_id=TENANT_A, secret_reference_id=None,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="live verification"):
        accepted_instance(
            connector_key="junos.device", mode="fixture", maturity="live_verified",
            configuration=configuration(), runner_id=TENANT_A, secret_reference_id=None,  # type: ignore[arg-type]
        )
    maturity, _parsed = accepted_instance(
        connector_key="junos.device", mode="fixture", maturity="experimental",
        configuration=configuration(), runner_id=TENANT_A, secret_reference_id=None,  # type: ignore[arg-type]
    )
    assert maturity == "fixture_tested"
    with pytest.raises(ValueError):
        accepted_job_input("junos.device", {"rpc": "<edit-config/>"})
    with pytest.raises(ValueError):
        parse_configuration("junos.device", "fixture", {**configuration(), "target_host": "evil.example"})
    with pytest.raises(ValueError):
        parse_configuration("junos.device", "live", {**_live_configuration(), "port": 22})
    with pytest.raises(ValueError):
        parse_configuration("junos.device", "live", {**_live_configuration(), "host_key_algorithm": "ssh-rsa"})
    with pytest.raises(ValueError):
        parse_configuration("junos.device", "live", {**_live_configuration(), "host_key_fingerprint": None, "known_hosts_reference": None})
    with pytest.raises(ValueError):
        parse_configuration("junos.device", "live", {**_live_configuration(), "known_hosts_reference": "/etc/ssh/known_hosts"})
    parsed = parse_configuration("junos.device", "live", {**_live_configuration(), "port": 443, "port_override": True})
    assert parsed["port"] == 443
    assert "evil.example" not in json.dumps(parsed)


def test_ssh_policy_and_dns_pinning_do_not_connect(monkeypatch) -> None:
    def explode(*_args, **_kwargs):
        raise AssertionError("network")

    monkeypatch.setattr(socket, "socket", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    monkeypatch.setattr(socket, "getaddrinfo", explode)
    host_key_accepted(PIN, PIN)
    with pytest.raises(CollectionFailure) as mismatch:
        host_key_accepted(PIN, OTHER)
    assert mismatch.value.code == "host_key_mismatch"
    with pytest.raises(CollectionFailure) as missing:
        host_key_accepted("", PIN)
    assert missing.value.code == "host_key_required"
    accept_algorithm("ssh-ed25519")
    with pytest.raises(CollectionFailure):
        accept_algorithm("ssh-rsa")
    with pytest.raises(CollectionFailure):
        accept_algorithm("diffie-hellman-group1-sha1")
    assert approved_port(830, False) == 830
    with pytest.raises(CollectionFailure):
        approved_port(22, False)
    assert approved_endpoint({"target_host": "10.8.0.1", "port": 830}, explode) == "10.8.0.1"
    with pytest.raises(CollectionFailure):
        approved_endpoint({"target_host": "169.254.169.254", "port": 830}, explode)
    with pytest.raises(CollectionFailure):
        approved_endpoint({"target_host": "127.0.0.1", "port": 830}, explode)
    answers = iter([["10.8.0.8"], ["10.8.0.8"]])
    assert pin_address("synthetic-edge.example", lambda _host: next(answers)) == "10.8.0.8"
    flipped = iter([["10.8.0.8"], ["10.8.0.9"]])
    with pytest.raises(CollectionFailure) as rebound:
        pin_address("synthetic-edge.example", lambda _host: next(flipped))
    assert rebound.value.code == "dns_rebinding"
    with pytest.raises(CollectionFailure) as unresolved:
        default_resolver("synthetic-edge.example")
    assert unresolved.value.code == "dns_resolution_unavailable"
    assert "HTTP_PROXY" not in ignored_proxy_environment({"HTTP_PROXY": "http://evil.example", "PATH": "/usr/bin"})
    assert CONNECT_TIMEOUT_SECONDS <= 10
    assert READ_TIMEOUT_SECONDS <= 20
    assert DNS_TIMEOUT_SECONDS <= 2
    assert SESSION_SECONDS <= 60
    assert MAX_CONNECT_ATTEMPTS <= 3


def test_live_path_fails_closed_without_a_socket(monkeypatch) -> None:
    def explode(*_args, **_kwargs):
        raise AssertionError("network")

    monkeypatch.setattr(socket, "socket", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    monkeypatch.setattr(socket, "getaddrinfo", explode)
    monkeypatch.delenv("THREATSIGHT_JUNOS_LIVE", raising=False)
    assert live_enabled() is False
    disabled = execute_claimed(
        _job(_live_configuration(), mode="live"), TENANT_A, WORKSPACE_A,
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True, clock=lambda: NOW,
    )
    assert disabled["code"] == "live_disabled"
    monkeypatch.setenv("THREATSIGHT_JUNOS_LIVE", "true")
    monkeypatch.setenv("THREATSIGHT_JUNOS_CREDENTIALS", json.dumps({
        "synthetic-locator": {"username": "netconf", "private_key": "placeholder-private-key-value-not-real"},
    }))
    refused = execute_claimed(
        _job(_live_configuration(), mode="live"), TENANT_A, WORKSPACE_A,
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True, clock=lambda: NOW,
    )
    assert refused["code"] == "secret_refused"
    assert "placeholder" not in json.dumps(refused)
    with pytest.raises(CollectionFailure) as direct:
        resolve_credential("synthetic-locator")
    assert direct.value.code == "secret_refused"
    assert "placeholder" not in str(direct.value)
    monkeypatch.setenv("THREATSIGHT_JUNOS_CREDENTIALS", json.dumps({
        "synthetic-locator": {"username": "netconf", "private_key": KEY},
    }))
    unavailable = execute_claimed(
        _job(_live_configuration(), mode="live"), TENANT_A, WORKSPACE_A,
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True, clock=lambda: NOW,
    )
    assert unavailable["code"] == "live_transport_unavailable"
    assert "PRIVATE KEY" not in json.dumps(unavailable)
    with pytest.raises(CollectionFailure) as closed:
        open_session(_live_configuration())
    assert closed.value.code == "live_transport_unavailable"
    assert KEY not in json.dumps(unavailable)
    foreign = execute_claimed(
        _job(_live_configuration(), mode="live"), "other-tenant", WORKSPACE_A,
        disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True, clock=lambda: NOW,
    )
    assert foreign["code"] == "tenant_mismatch"
    assert "PRIVATE KEY" not in json.dumps(foreign)


def test_session_limit_and_no_shell_or_ssh_library() -> None:
    connector = build_connector("junos.device", {**configuration(), "mode": "fixture"}, FixtureTransport("nordic-retail"), lambda: NOW)
    connector._started -= SESSION_SECONDS + 5
    with pytest.raises(CollectionFailure) as expired:
        connector.collect(Capability.INVENTORY, PageRequest())
    assert expired.value.code == "session_limit"
    root = Path(device_module.__file__).resolve().parent
    source = "\n".join(path.read_text() for path in root.glob("*.py"))
    for banned in ("subprocess", "paramiko", "ncclient", "os.system", "tempfile", "getaddrinfo", "create_connection"):
        assert banned not in source
    api_source = inspect.getsource(connectors_api)
    assert "open_session" not in api_source
    assert "paramiko" not in api_source


def _live_configuration() -> dict:
    return {
        "device_id": DEVICE,
        "target_host": "10.8.0.1",
        "port": 830,
        "host_key_fingerprint": PIN,
        "host_key_algorithm": "ssh-ed25519",
    }
