"""Register the reference connectors without giving them a separate execution path."""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from threatsight_api.connectors.junos.bounds import ACCEPTED_ALGORITHMS, DEVICE_ID, FINGERPRINT, LOCATOR
from threatsight_api.connectors.junos.device import JunosConnector
from threatsight_api.connectors.meraki.bounds import ORG_ID
from threatsight_api.connectors.meraki.dashboard import MerakiDashboardConnector
from threatsight_api.connectors.microsoft.arg import AzureResourceGraphConnector
from threatsight_api.connectors.microsoft.entra import EntraConnector
from threatsight_api.connectors.microsoft.fixtures import FixtureTransport as MicrosoftFixtureTransport

CUSTOMER_RESIDENT = frozenset({"azure.resource_graph", "entra.identity", "meraki.dashboard", "junos.device"})
MerakiFixtureName = Literal[
    "nordic-retail", "empty", "empty-network", "missing-optional", "forbidden", "license",
    "throttled", "transient", "malformed", "oversized", "excessive", "malicious-link",
    "redirect", "duplicates", "dangling", "invalid-subnet", "paged", "partial", "stale", "conflicting",
]
FixtureName = Literal[
    "nordic-retail", "empty", "missing-optional", "forbidden", "throttled", "transient",
    "malformed", "oversized", "excessive", "duplicates", "dangling", "conflicting", "partial",
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AzureFixture(Strict):
    fixture: FixtureName = "nordic-retail"
    microsoft_tenant_id: uuid.UUID
    subscription_ids: list[uuid.UUID] = Field(min_length=1, max_length=5)


class AzureLive(Strict):
    microsoft_tenant_id: uuid.UUID
    subscription_ids: list[uuid.UUID] = Field(min_length=1, max_length=5)


class EntraFixture(Strict):
    fixture: FixtureName = "nordic-retail"
    microsoft_tenant_id: uuid.UUID
    subscription_ids: list[uuid.UUID] = Field(default_factory=list, max_length=5)


class EntraLive(Strict):
    microsoft_tenant_id: uuid.UUID
    subscription_ids: list[uuid.UUID] = Field(default_factory=list, max_length=5)


class MerakiFixture(Strict):
    fixture: MerakiFixtureName = "nordic-retail"
    organization_ids: list[str] = Field(min_length=1, max_length=5)


class MerakiLive(Strict):
    organization_ids: list[str] = Field(min_length=1, max_length=5)


JunosFixtureName = Literal[
    "nordic-retail", "stale", "conflicting", "unsupported", "malformed", "xxe", "entities",
    "oversized", "deep", "wide", "malicious-namespace", "invalid-prefix", "duplicate", "dangling",
    "full-table", "host-key-mismatch", "missing-host-key", "auth-rejected", "timeout", "reconnect",
    "partial", "log-injection",
]


class JunosFixture(Strict):
    fixture: JunosFixtureName = "nordic-retail"
    device_id: str
    host_key_fingerprint: str | None = None
    host_key_algorithm: str | None = None

    @field_validator("device_id")
    @classmethod
    def device(cls, value: str) -> str:
        if DEVICE_ID.fullmatch(value) is None:
            raise ValueError("device")
        return value

    @field_validator("host_key_fingerprint")
    @classmethod
    def fingerprint(cls, value: str | None) -> str | None:
        if value is not None and FINGERPRINT.fullmatch(value) is None:
            raise ValueError("fingerprint")
        return value

    @field_validator("host_key_algorithm")
    @classmethod
    def algorithm(cls, value: str | None) -> str | None:
        if value is not None and value not in ACCEPTED_ALGORITHMS:
            raise ValueError("algorithm")
        return value


class JunosLive(Strict):
    device_id: str
    target_host: str
    port: int = 830
    port_override: bool = False
    host_key_fingerprint: str | None = None
    known_hosts_reference: str | None = None
    host_key_algorithm: str

    @field_validator("device_id")
    @classmethod
    def device(cls, value: str) -> str:
        if DEVICE_ID.fullmatch(value) is None:
            raise ValueError("device")
        return value

    @field_validator("host_key_fingerprint")
    @classmethod
    def fingerprint(cls, value: str | None) -> str | None:
        if value is not None and FINGERPRINT.fullmatch(value) is None:
            raise ValueError("fingerprint")
        return value

    @field_validator("known_hosts_reference")
    @classmethod
    def known_hosts(cls, value: str | None) -> str | None:
        if value is not None and LOCATOR.fullmatch(value) is None:
            raise ValueError("known_hosts")
        return value

    @field_validator("host_key_algorithm")
    @classmethod
    def algorithm(cls, value: str) -> str:
        if value not in ACCEPTED_ALGORITHMS:
            raise ValueError("algorithm")
        return value

    @field_validator("target_host")
    @classmethod
    def host(cls, value: str) -> str:
        if any(ord(char) < 33 for char in value) or "/" in value or "@" in value:
            raise ValueError("host")
        return value.lower()

    @model_validator(mode="after")
    def pin_and_port(self):
        if self.port != 830 and not self.port_override:
            raise ValueError("port")
        if not 1 <= self.port <= 65535:
            raise ValueError("port")
        if self.host_key_fingerprint is None and self.known_hosts_reference is None:
            raise ValueError("host_key")
        return self


_MODELS = {
    "azure.resource_graph": {"fixture": AzureFixture, "live": AzureLive},
    "entra.identity": {"fixture": EntraFixture, "live": EntraLive},
    "meraki.dashboard": {"fixture": MerakiFixture, "live": MerakiLive},
    "junos.device": {"fixture": JunosFixture, "live": JunosLive},
}


def _contains_url(value: object) -> bool:
    if isinstance(value, str):
        return "://" in value or value.strip().lower().startswith("http")
    if isinstance(value, dict):
        return any(_contains_url(item) or _contains_url(key) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_url(item) for item in value)
    return False


def parse_configuration(connector_key: str, mode: str, configuration: dict) -> dict:
    if connector_key not in CUSTOMER_RESIDENT or mode not in _MODELS[connector_key] or not isinstance(configuration, dict):
        raise ValueError("connector configuration is invalid")
    if _contains_url(configuration):
        raise ValueError("connector configuration is invalid")
    try:
        parsed = _MODELS[connector_key][mode].model_validate(configuration).model_dump(mode="json")
    except ValidationError:
        raise ValueError("connector configuration is invalid") from None
    identities = [str(item) for item in parsed.get("subscription_ids", parsed.get("organization_ids", []))]
    if len(identities) != len(set(identities)):
        raise ValueError("connector configuration is invalid")
    if connector_key == "meraki.dashboard" and any(ORG_ID.fullmatch(item) is None for item in identities):
        raise ValueError("connector configuration is invalid")
    parsed["mode"] = mode
    return parsed


def accepted_instance(
    *,
    connector_key: str,
    mode: str,
    maturity: str,
    configuration: dict,
    runner_id: uuid.UUID | None,
    secret_reference_id: uuid.UUID | None,
) -> tuple[str, dict]:
    if maturity == "live_verified":
        raise ValueError("maturity is assigned only after live verification")
    if connector_key not in CUSTOMER_RESIDENT:
        return maturity, configuration
    if runner_id is None:
        raise ValueError("this connector requires a customer runner")
    if mode == "live" and secret_reference_id is None:
        raise ValueError("live collection requires a secret reference")
    parsed = parse_configuration(connector_key, mode, configuration)
    return ("fixture_tested" if mode == "fixture" else "experimental"), parsed


def accepted_job_input(connector_key: str, value: dict) -> dict:
    if connector_key in CUSTOMER_RESIDENT and value:
        raise ValueError("this connector does not accept client collection input")
    return value


def build_connector(connector_key: str, configuration: dict, transport=None, clock=None, graph_token: str = "", arm_token: str = "", api_key: str = ""):
    if connector_key not in CUSTOMER_RESIDENT:
        return None
    selected = transport
    if selected is None and configuration.get("mode") == "fixture":
        if connector_key == "meraki.dashboard":
            from threatsight_api.connectors.meraki.fixtures import FixtureTransport
            selected = FixtureTransport(str(configuration.get("fixture", "")))
        elif connector_key == "junos.device":
            from threatsight_api.connectors.junos.fixtures import FixtureTransport
            selected = FixtureTransport(str(configuration.get("fixture", "")))
        else:
            selected = MicrosoftFixtureTransport(str(configuration.get("fixture", "")))
    if selected is None and connector_key == "meraki.dashboard":
        from threatsight_api.connectors.meraki.transport import LiveTransport
        selected = LiveTransport()
    if selected is None and connector_key == "junos.device":
        from threatsight_api.connectors.junos.live import ClosedTransport
        selected = ClosedTransport()
    if selected is None:
        from threatsight_api.connectors.microsoft.transport import LiveTransport
        selected = LiveTransport()
    if connector_key == "azure.resource_graph":
        return AzureResourceGraphConnector(configuration, selected, arm_token or graph_token, clock)
    if connector_key == "meraki.dashboard":
        return MerakiDashboardConnector(configuration, selected, api_key, clock)
    if connector_key == "junos.device":
        return JunosConnector(configuration, selected, clock)
    return EntraConnector(configuration, selected, graph_token, arm_token or graph_token, clock)
