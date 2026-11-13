from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from threatsight_api.connectors.meraki.bounds import (
    MAX_RESPONSE_BYTES,
    CollectionFailure,
    approved_url,
    clean_ip,
    clean_subnet,
    credential_refused,
)
from threatsight_api.connectors.meraki.fixtures import (
    BRANCH_EDGE,
    EDGE,
    ORG_BRANCH,
    ORG_HQ,
    ORG_MISSING,
    ORG_UNSELECTED,
    PUBLIC_HQ,
    FixtureTransport,
    configuration,
)
from threatsight_api.connectors.meraki.live import collection_origin, resolve_api_key
from threatsight_api.connectors.meraki.paging import next_link
from threatsight_api.connectors.meraki.transport import VendorRequest, decode_payload, transmit
from threatsight_api.connectors.microsoft.dispatch import execute_claimed, run_collection
from threatsight_api.connectors.microsoft.registry import accepted_instance, accepted_job_input, parse_configuration

NOW = datetime(2026, 10, 30, tzinfo=UTC)
JOB_ID = "11111111-1111-4111-8111-111111111111"
TENANT_A = "22222222-2222-4222-8222-222222222222"
WORKSPACE_A = "33333333-3333-4333-8333-333333333333"
SECRET = "abcd1234abcd1234abcd1234abcd1234"


def _job(configuration_body: dict, *, mode: str = "fixture", tenant: str = TENANT_A, workspace: str = WORKSPACE_A) -> dict:
    body = dict(configuration_body)
    body["mode"] = mode
    return {
        "id": JOB_ID,
        "idempotency_key": "meraki-inventory",
        "job_type": "inventory",
        "dispatch": {
            "connector_key": "meraki.dashboard",
            "mode": mode,
            "configuration": body,
            "secret_locator": "synthetic-locator",
            "tenant_id": tenant,
            "workspace_id": workspace,
        },
    }


def _run(fixture: str = "nordic-retail", organization_ids: list[str] | None = None, **kwargs):
    return run_collection(
        _job(configuration(fixture, organization_ids)),
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


def test_bounded_collection_is_deterministic_and_minimized() -> None:
    first = _run()
    second = _run()
    assert first.maturity == "fixture_tested"
    assert first.content_hash == second.content_hash
    dumped = _dump(first)
    kinds = _kinds(first)
    assert {item.attributes["organization_id"] for item in kinds["organization"]} == {ORG_HQ, ORG_BRANCH}
    assert ORG_UNSELECTED not in dumped
    assert EDGE in dumped and BRANCH_EDGE in dumped and PUBLIC_HQ in dumped
    assert "10.8.0.0/24" in dumped
    assert "Synthetic headquarters INJECT" in dumped
    for forbidden in ("api_key", "secret-shaped", "person@", "Bearer", "evil.example", "\n", "notes", "mac", "lat", "address"):
        assert forbidden not in dumped
    assert all(record.truth_state != "live_verified" for record in first.records)


def test_explicit_organization_selection_ignores_unselected_organizations() -> None:
    transport = FixtureTransport("nordic-retail")
    envelope = _run(organization_ids=[ORG_HQ, ORG_MISSING], transport=transport)
    dumped = _dump(envelope)
    assert BRANCH_EDGE not in dumped and ORG_UNSELECTED not in dumped
    missing = next(record for record in envelope.records if record.attributes.get("organization_id") == ORG_MISSING)
    assert missing.truth_state == "unknown"
    assert "missing_or_inaccessible" in missing.limitations
    assert all(ORG_MISSING not in call and ORG_BRANCH not in call and ORG_UNSELECTED not in call for call in transport.calls)


def test_network_pagination_follows_only_validated_links() -> None:
    transport = FixtureTransport("paged")
    envelope = _run("paged", organization_ids=[ORG_HQ], transport=transport)
    networks = [record.attributes["network_id"] for record in envelope.records if record.kind == "network"]
    assert networks == ["L_900000001001", "L_900000001002"]
    assert sum("startingAfter=" in call for call in transport.calls) == 1
    assert all(call.startswith("https://api.meraki.com/api/v1/") for call in transport.calls)


def test_empty_organization_and_empty_network_are_explicit() -> None:
    empty = _kinds(_run("empty", organization_ids=[ORG_HQ]))
    assert list(empty) == ["collection_status", "organization"] or set(empty) == {"organization", "collection_status"}
    assert "network" not in empty
    networked = _kinds(_run("empty-network", organization_ids=[ORG_HQ]))
    assert len(networked["network"]) == 1
    assert "device" not in networked


def test_missing_product_and_license_are_unsupported() -> None:
    missing = _run("missing-optional")
    licensed = _run("license")
    assert any(record.truth_state == "unsupported" and "product_unavailable" in record.limitations for record in missing.records)
    assert any(record.kind == "device" for record in missing.records)
    assert any("permission_unavailable" not in record.limitations and record.truth_state == "unsupported" for record in licensed.records)
    assert any(record.kind == "device" for record in licensed.records)


def test_permission_rate_limit_transient_and_malformed_responses() -> None:
    with pytest.raises(CollectionFailure) as denied:
        _run("forbidden")
    assert denied.value.code == "permission_denied"
    throttled_transport = FixtureTransport("throttled")
    throttled = _run("throttled", transport=throttled_transport)
    assert _status(throttled).attributes["retry_after_seconds"] == 2
    assert len(throttled_transport.calls) == 1
    transient = FixtureTransport("transient")
    envelope = _run("transient", transport=transient)
    assert envelope.maturity == "fixture_tested"
    assert transient.calls.count("https://api.meraki.com/api/v1/organizations?perPage=100") == 2
    partial = _run("partial", organization_ids=[ORG_HQ])
    assert _status(partial).attributes["partial"] is True
    assert any(record.kind == "network" for record in partial.records)
    assert not any(record.kind == "device" for record in partial.records)
    with pytest.raises(CollectionFailure) as malformed:
        _run("malformed")
    assert malformed.value.code == "malformed_response"
    with pytest.raises(CollectionFailure) as oversized:
        _run("oversized")
    assert oversized.value.code == "response_too_large"


def test_pagination_limits_malicious_links_and_redirects() -> None:
    excessive = FixtureTransport("excessive")
    capped = _run("excessive", organization_ids=[ORG_HQ], transport=excessive)
    assert len(excessive.calls) <= 3
    assert _status(capped).attributes["partial"] is True
    malicious = FixtureTransport("malicious-link")
    rejected = _run("malicious-link", organization_ids=[ORG_HQ], transport=malicious)
    assert _status(rejected).attributes["partial"] is True
    assert all("evil.example" not in call for call in malicious.calls)
    redirected = FixtureTransport("redirect")
    with pytest.raises(CollectionFailure) as redirect:
        _run("redirect", transport=redirected)
    assert redirect.value.code == "redirect_refused"
    assert redirected.calls == ["https://api.meraki.com/api/v1/organizations?perPage=100"]


def test_duplicates_dangling_invalid_addresses_and_stale_sources() -> None:
    duplicates = _run("duplicates")
    assert any("duplicate_collapsed" in record.limitations for record in duplicates.records)
    dangling = _run("dangling", organization_ids=[ORG_HQ])
    device = next(record for record in dangling.records if record.external_id == f"device:{EDGE}")
    assert device.attributes["association_state"] == "unknown"
    invalid = _dump(_run("invalid-subnet", organization_ids=[ORG_HQ]))
    assert "not-a-cidr" not in invalid and "999.1.1.1" not in invalid and "not-an-ip" not in invalid
    stale = _run("stale", organization_ids=[ORG_HQ])
    assert any(record.truth_state == "stale" for record in stale.records)
    conflicting = _run("conflicting", organization_ids=[ORG_HQ])
    assert any(record.truth_state == "conflicting" for record in conflicting.records)


def test_cancellation_kill_switch_and_expired_lease() -> None:
    for gate, limitation in (("cancelled", "cancelled"), ("disabled", "kill_switch")):
        transport = FixtureTransport("nordic-retail")
        flags = {"cancelled": False, "disabled": False}
        original = transport.send_once

        def send_once(request, token, original=original, gate=gate):
            result = original(request, token)
            flags[gate] = True
            return result

        transport.send_once = send_once
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
        assert len(transport.calls) == 1

    transport = FixtureTransport("nordic-retail")
    original = transport.send_once
    flags = {"ok": True}

    def expire(request, token, original=original):
        result = original(request, token)
        flags["ok"] = False
        return result

    transport.send_once = expire
    result = execute_claimed(
        _job(configuration()),
        TENANT_A,
        WORKSPACE_A,
        disabled=lambda: False,
        cancelled=lambda: False,
        lease_ok=lambda: flags["ok"],
        clock=lambda: NOW,
        transport=transport,
    )
    assert result == {"action": "stop"}
    assert len(transport.calls) == 1


def test_cross_tenant_and_configuration_rejection() -> None:
    transport = FixtureTransport("nordic-retail")
    result = execute_claimed(
        _job(configuration()),
        "other-tenant",
        WORKSPACE_A,
        disabled=lambda: False,
        cancelled=lambda: False,
        lease_ok=lambda: True,
        transport=transport,
    )
    assert result["code"] == "tenant_mismatch"
    assert transport.calls == []
    with pytest.raises(ValueError):
        parse_configuration("meraki.dashboard", "fixture", {**configuration(), "base_url": "https://evil.example"})
    with pytest.raises(ValueError):
        parse_configuration("meraki.dashboard", "live", {"organization_ids": []})
    with pytest.raises(ValueError):
        accepted_job_input("meraki.dashboard", {"organization_ids": [ORG_HQ]})
    with pytest.raises(ValueError, match="live verification"):
        accepted_instance(
            connector_key="meraki.dashboard", mode="fixture", maturity="live_verified",
            configuration=configuration(), runner_id=TENANT_A, secret_reference_id=None,  # type: ignore[arg-type]
        )
    maturity, parsed = accepted_instance(
        connector_key="meraki.dashboard", mode="fixture", maturity="experimental",
        configuration=configuration(), runner_id=TENANT_A, secret_reference_id=None,  # type: ignore[arg-type]
    )
    assert maturity == "fixture_tested"
    assert parsed["organization_ids"] == [ORG_HQ, ORG_BRANCH]


def test_link_parser_and_address_bounds() -> None:
    origin = "https://api.meraki.com"
    path = "/api/v1/organizations"
    header = f'<{origin}{path}?perPage=100&startingAfter=900000001>; rel="next"'
    assert next_link(header, origin=origin, path=path) == f"{origin}{path}?perPage=100&startingAfter=900000001"
    with pytest.raises(CollectionFailure):
        next_link('<https://evil.example/api/v1/organizations?perPage=100>; rel=next', origin=origin, path=path)
    with pytest.raises(CollectionFailure):
        approved_url("https://user:key@api.meraki.com/api/v1/organizations")
    with pytest.raises(CollectionFailure):
        approved_url("https://api.meraki.com:444/api/v1/organizations")
    with pytest.raises(CollectionFailure):
        transmit(FixtureTransport("nordic-retail"), VendorRequest("POST", f"{origin}{path}"), "")
    assert clean_ip("203.0.113.10") == "203.0.113.10"
    assert clean_ip("127.0.0.1") is None
    assert clean_subnet("10.8.0.1/24") == "10.8.0.0/24"
    assert clean_subnet("not-a-cidr") is None
    with pytest.raises(CollectionFailure):
        decode_payload(b"x" * (MAX_RESPONSE_BYTES + 1))
    with pytest.raises(CollectionFailure):
        decode_payload(b"{")


def test_live_collection_is_opt_in_and_redacts_the_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("THREATSIGHT_MERAKI_LIVE", raising=False)
    job = _job(configuration(organization_ids=[ORG_HQ]), mode="live")
    with pytest.raises(CollectionFailure) as disabled:
        run_collection(job, disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True, clock=lambda: NOW)
    assert disabled.value.code == "live_disabled"
    monkeypatch.setenv("THREATSIGHT_MERAKI_LIVE", "true")
    monkeypatch.setenv("THREATSIGHT_MERAKI_CREDENTIALS", json.dumps({
        "synthetic-locator": {"api_key": "placeholder-credential-value"},
    }))
    with pytest.raises(CollectionFailure) as refused:
        resolve_api_key("synthetic-locator")
    assert refused.value.code == "secret_refused"
    assert "placeholder" not in str(refused.value)
    assert credential_refused("placeholder-credential-value")
    monkeypatch.setenv("THREATSIGHT_MERAKI_CREDENTIALS", json.dumps({"synthetic-locator": {"api_key": SECRET}}))

    class Scripted:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def send_once(self, request, token):
            self.calls.append(request.url)
            assert token == SECRET
            if request.url.endswith("/organizations?perPage=100"):
                from threatsight_api.connectors.meraki.transport import VendorResponse
                return VendorResponse(200, {}, [{"id": ORG_HQ, "name": "Synthetic headquarters"}])
            from threatsight_api.connectors.meraki.transport import VendorResponse
            return VendorResponse(200, {}, [])

    scripted = Scripted()
    envelope = run_collection(
        job, disabled=lambda: False, cancelled=lambda: False, lease_ok=lambda: True,
        clock=lambda: NOW, transport=scripted,
    )
    assert envelope.maturity == "live_verified"
    assert SECRET not in _dump(envelope)
    assert scripted.calls and all(call.startswith("https://api.meraki.com/") for call in scripted.calls)
    monkeypatch.setenv("THREATSIGHT_ENV", "production")
    monkeypatch.setenv("THREATSIGHT_MERAKI_TEST_ORIGIN", "http://127.0.0.1:9")
    with pytest.raises(CollectionFailure):
        collection_origin()
    monkeypatch.setenv("THREATSIGHT_ENV", "test")
    assert collection_origin() == "http://127.0.0.1:9"


def test_runner_requirement_and_write_methods_are_rejected() -> None:
    with pytest.raises(ValueError, match="customer runner"):
        accepted_instance(
            connector_key="meraki.dashboard", mode="fixture", maturity="experimental",
            configuration=configuration(), runner_id=None, secret_reference_id=None,
        )
    with pytest.raises(ValueError, match="secret reference"):
        accepted_instance(
            connector_key="meraki.dashboard", mode="live", maturity="experimental",
            configuration={"organization_ids": [ORG_HQ]}, runner_id=TENANT_A, secret_reference_id=None,  # type: ignore[arg-type]
        )
