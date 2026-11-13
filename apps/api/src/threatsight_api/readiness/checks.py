"""Versioned allowlisted read-only checks. No write or shell capability."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Check:
    id: str
    version: str
    connector: str
    capability: str
    title: str
    expected_data: str
    operational_impact: str
    result_mapping: str
    limitations: tuple[str, ...]
    live_supported: bool
    maturity: str
    secret_reference_required: bool = False


CHECKS: dict[str, Check] = {
    "azure.inventory.freshness.v1": Check(
        id="azure.inventory.freshness.v1",
        version="v1",
        connector="azure",
        capability="inventory",
        title="Azure resource inventory freshness",
        expected_data="Last inventory collection time and recorded software identifiers.",
        operational_impact="Read-only inventory collection. No configuration change.",
        result_mapping="fresh->observed;stale->configured_not_observed;missing->unknown",
        limitations=("synthetic_reference", "not_control_effectiveness"),
        live_supported=False,
        maturity="fixture_tested",
    ),
    "azure.public_address.config.v1": Check(
        id="azure.public_address.config.v1",
        version="v1",
        connector="azure",
        capability="configuration_evidence",
        title="Azure public-address configuration evidence",
        expected_data="Configured public address bindings.",
        operational_impact="Read-only configuration evidence. No network change.",
        result_mapping="present->configured_not_observed;absent->unknown",
        limitations=("synthetic_reference", "not_packet_delivery"),
        live_supported=False,
        maturity="fixture_tested",
    ),
    "entra.privileged_assignment.direct.v1": Check(
        id="entra.privileged_assignment.direct.v1",
        version="v1",
        connector="entra",
        capability="inventory",
        title="Direct privileged assignment evidence",
        expected_data="Direct privileged role assignments and collection freshness.",
        operational_impact="Read-only directory evidence. No membership change.",
        result_mapping="present->configured_not_observed;missing->unknown",
        limitations=("synthetic_reference", "not_control_effectiveness"),
        live_supported=False,
        maturity="fixture_tested",
    ),
    "meraki.firmware.recorded.v1": Check(
        id="meraki.firmware.recorded.v1",
        version="v1",
        connector="meraki",
        capability="inventory",
        title="Recorded Meraki firmware version",
        expected_data="Firmware version reported by the dashboard inventory.",
        operational_impact="Read-only inventory. No firmware upgrade.",
        result_mapping="present->configured_not_observed;missing->unknown",
        limitations=("synthetic_reference", "not_packet_delivery"),
        live_supported=False,
        maturity="fixture_tested",
    ),
    "junos.version.recorded.v1": Check(
        id="junos.version.recorded.v1",
        version="v1",
        connector="junos",
        capability="inventory",
        title="Recorded Junos software version",
        expected_data="Recorded software version from the last configuration snapshot.",
        operational_impact="Read-only configuration evidence. Live NETCONF remains unavailable until a safe transport exists.",
        result_mapping="present->configured_not_observed;missing->unknown",
        limitations=("synthetic_reference", "not_packet_delivery", "live_netconf_unavailable"),
        live_supported=False,
        maturity="fixture_tested",
    ),
    "synthetic.version.validate.v1": Check(
        id="synthetic.version.validate.v1",
        version="v1",
        connector="synthetic-fixture",
        capability="inventory",
        title="Validate recorded installed version",
        expected_data="Installed product version for the synthetic service member.",
        operational_impact="Fixture-tested collection only. No customer device is contacted.",
        result_mapping="present->configured_not_observed;missing->unknown",
        limitations=("synthetic_reference", "not_control_effectiveness", "not_packet_delivery"),
        live_supported=False,
        maturity="fixture_tested",
    ),
    "inventory_config_verify_iot2050": Check(
        id="inventory_config_verify_iot2050",
        version="1",
        connector="synthetic-fixture",
        capability="configuration_evidence",
        title="Validate SIMATIC IoT2050 version and Node-RED configuration",
        expected_data="Recorded industrial OS version, Node-RED installation, authentication configuration, and reachability evidence.",
        operational_impact="Reference-data validation only. No customer device or industrial network is contacted.",
        result_mapping="present->configured_not_observed;missing->unknown",
        limitations=("synthetic_reference", "not_control_effectiveness", "not_packet_delivery", "not_customer_exposure"),
        live_supported=False,
        maturity="fixture_tested",
    ),
}


def get_check(check_id: str) -> Check | None:
    return CHECKS.get(check_id)


def require_check(check_id: str) -> Check:
    check = get_check(check_id)
    if check is None:
        raise ValueError("check_not_allowlisted")
    return check
