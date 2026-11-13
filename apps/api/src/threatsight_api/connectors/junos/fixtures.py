"""Sanitized Nordic Retail NETCONF replies. Nothing here is a real device."""

from __future__ import annotations

from datetime import UTC, datetime

from threatsight_api.connectors.junos.bounds import MAX_DEPTH, MAX_NODES, MAX_XML_BYTES, CollectionFailure
from threatsight_api.connectors.junos.rpc import assert_allowed
from threatsight_api.connectors.junos.target import host_key_accepted

NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
PIN = "SHA256:" + ("A" * 43)
OTHER = "SHA256:" + ("B" * 43)
DEVICE = "synth-junos-edge-01"
_ATTACKS = {"malformed", "xxe", "entities", "oversized", "deep", "wide", "malicious-namespace"}
_NAMES = _ATTACKS | {
    "nordic-retail", "stale", "conflicting", "unsupported", "invalid-prefix", "duplicate",
    "dangling", "full-table", "host-key-mismatch", "missing-host-key", "auth-rejected",
    "timeout", "reconnect", "partial", "log-injection",
}


def _reply(body: str) -> bytes:
    return f'<rpc-reply xmlns="{NS}">{body}</rpc-reply>'.encode()


def _hello(junos: bool) -> bytes:
    capabilities = [
        "urn:ietf:params:netconf:base:1.0",
        "urn:ietf:params:netconf:base:1.1",
    ]
    if junos:
        capabilities.extend([
            "http://xml.juniper.net/netconf/junos/1.0",
            "urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file",
        ])
    inner = "".join(f"<capability>{item}</capability>" for item in capabilities)
    return f'<hello xmlns="{NS}"><capabilities>{inner}</capabilities></hello>'.encode()


def _system(hostname: str) -> bytes:
    return _reply(
        "<system-information>"
        "<hardware-model>SRX-SYN</hardware-model>"
        "<os-version>23.4R1-synthetic</os-version>"
        f"<host-name>{hostname}</host-name>"
        "<serial-number>SYNTHCHASSIS0001</serial-number>"
        "</system-information><!-- comment-shaped-secret -->"
    )


def _interfaces(oper: str = "up", duplicate: bool = False) -> bytes:
    def physical(name: str, logical: str, status: str) -> str:
        return (
            "<physical-interface>"
            f"<name>{name}</name><admin-status>up</admin-status><oper-status>{status}</oper-status>"
            "<description>IGNORE-THIS-TEXT</description>"
            f"<logical-interface><name>{logical}</name><admin-status>up</admin-status>"
            f"<oper-status>{status}</oper-status></logical-interface></physical-interface>"
        )

    blocks = [
        physical("ge-0/0/0", "ge-0/0/0.0", oper),
        physical("ge-0/0/1", "ge-0/0/1.0", "up"),
        physical("fxp0", "fxp0.0", "up"),
        physical("st0", "st0.0", "up"),
    ]
    if duplicate:
        blocks.insert(1, physical("ge-0/0/0", "ge-0/0/0.0", oper))
    return _reply(f"<interface-information>{''.join(blocks)}</interface-information>")


def _configured_interfaces(invalid: bool = False) -> bytes:
    rows = [
        ("ge-0/0/0", "0", "203.0.113.10/24"),
        ("ge-0/0/1", "0", "10.8.0.1/24"),
        ("fxp0", "0", "10.255.0.1/24"),
        ("st0", "0", "10.255.1.1/30"),
    ]
    if invalid:
        rows.append(("ge-0/0/1", "0", "999.1.1.1/99"))
    body = []
    for name, unit, address in rows:
        body.append(
            f"<interface><name>{name}</name><unit><name>{unit}</name><family><inet><address>"
            f"<name>{address}</name></address></inet></family></unit></interface>"
        )
    return _reply(f"<configuration><interfaces>{''.join(body)}</interfaces></configuration>")


def _zones(dangling: bool = False) -> bytes:
    management = "<interfaces><name>ge-0/0/9.0</name></interfaces>" if dangling else ""
    management += "<interfaces><name>fxp0.0</name></interfaces>"
    body = (
        "<security><zones>"
        "<security-zone><name>untrust</name><interfaces><name>ge-0/0/0.0</name></interfaces>"
        "<host-inbound-traffic><protocols><name>ping</name></protocols></host-inbound-traffic></security-zone>"
        "<security-zone><name>trust</name><interfaces><name>ge-0/0/1.0</name></interfaces></security-zone>"
        "<security-zone><name>management</name>"
        f"{management}"
        "<host-inbound-traffic><system-services><name>ssh</name></system-services>"
        "<system-services><name>netconf</name></system-services></host-inbound-traffic></security-zone>"
        "</zones></security>"
    )
    return _reply(body)


def _policies(duplicate: bool = False) -> bytes:
    allow_rule = (
        "<policy><name>branch-egress</name><match><source-address>synth-internal</source-address>"
        "<destination-address>any</destination-address><application>any</application></match>"
        "<then><permit/><log><session-init/></log></then></policy>"
    )
    body = (
        "<security><policies>"
        "<policy><from-zone-name>trust</from-zone-name><to-zone-name>untrust</to-zone-name>"
        f"{allow_rule}{allow_rule if duplicate else ''}</policy>"
        "<policy><from-zone-name>untrust</from-zone-name><to-zone-name>trust</to-zone-name>"
        "<policy><name>edge-deny</name><match><source-address>any</source-address>"
        "<destination-address>synth-internal</destination-address><application>any</application></match>"
        "<then><deny/></then></policy></policy>"
        "<address-book><name>unrelated</name><address><name>unrelated-object</name>"
        "<ip-prefix>198.51.100.0/24</ip-prefix></address></address-book>"
        "</policies></security>"
    )
    return _reply(body)


def _route(destination: str, hop: str = "10.8.0.2", via: str = "ge-0/0/1.0") -> str:
    return (
        f"<rt><rt-destination>{destination}</rt-destination><rt-entry><protocol-name>Static</protocol-name>"
        f"<nh><to>{hop}</to><via>{via}</via></nh></rt-entry></rt>"
    )


def _routes(extra: list[str] | None = None, count: int = 0) -> bytes:
    rows = [
        _route("0.0.0.0/0", "203.0.113.1", "ge-0/0/0.0"),
        _route("10.9.0.0/24"),
    ]
    rows.extend(_route(item) for item in extra or [])
    rows.extend(_route(f"10.20.{index}.0/24") for index in range(count))
    return _reply(f"<route-information><route-table><table-name>inet.0</table-name>{''.join(rows)}</route-table></route-information>")


def _routing() -> bytes:
    return _reply(
        "<configuration><routing-instances><instance><name>synth-vr</name>"
        "<instance-type>virtual-router</instance-type><interface><name>ge-0/0/1.0</name></interface>"
        "</instance></routing-instances></configuration>"
    )


def _vpn() -> bytes:
    return _reply(
        "<configuration><security><ike><gateway><name>synth-branch</name>"
        "<external-interface>ge-0/0/0.0</external-interface><address>203.0.113.20</address>"
        "<pre-shared-key>secret-shaped-value</pre-shared-key><ike-sa-state>UP</ike-sa-state></gateway></ike>"
        "<ipsec><vpn><name>synth-branch-vpn</name><bind-interface>st0.0</bind-interface>"
        "<ike><gateway>synth-branch</gateway></ike></vpn></ipsec></security>"
        "<certificate>BEGIN CERTIFICATE synthetic</certificate></configuration>"
    )


def _services() -> bytes:
    return _reply(
        "<configuration><system><services><ssh/><netconf><ssh/></netconf>"
        "<web-management><http/></web-management></services>"
        "<snmp><community>public-shaped</community></snmp>"
        "<login><user><name>operator-shaped</name><authentication>"
        "<encrypted-password>hash-shaped-value</encrypted-password></authentication></user></login>"
        "<radius-server><secret>radius-shaped</secret></radius-server></system></configuration>"
    )


def _attack(name: str) -> bytes:
    if name == "malformed":
        return b"<rpc-reply>"
    if name == "xxe":
        return (
            b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            b'<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">&xxe;</rpc-reply>'
        )
    if name == "entities":
        return (
            b'<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
            b'<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">&lol2;</rpc-reply>'
        )
    if name == "oversized":
        return b"x" * (MAX_XML_BYTES + 1)
    if name == "deep":
        inner = "<item/>"
        for _ in range(MAX_DEPTH + 2):
            inner = f"<item>{inner}</item>"
        return _reply(inner)
    if name == "wide":
        return _reply("".join("<item/>" for _ in range(MAX_NODES + 1)))
    return b'<rpc-reply xmlns="http://evil.example/ns"><host-name>synth-edge</host-name></rpc-reply>'


def document(name: str, operation: str) -> bytes:
    if name in _ATTACKS:
        return _attack(name)
    if operation == "hello":
        return _hello(name != "unsupported")
    if operation == "get-system-information":
        return _system("synth-edge\nINJECTED" if name == "log-injection" else "synth-edge")
    if operation == "get-interface-information":
        return _interfaces("down" if name == "conflicting" else "up", name == "duplicate")
    if operation == "get-config-interfaces":
        return _configured_interfaces(name == "invalid-prefix")
    if operation == "get-config-zones":
        return _zones(name == "dangling")
    if operation == "get-config-policies":
        return _policies(name == "duplicate")
    if operation == "get-route-information":
        if name == "full-table":
            return _routes(count=12)
        if name == "invalid-prefix":
            return _routes(["10.8.0.1/24", "999.1.1.1/99"])
        return _routes()
    if operation == "get-config-routing":
        return _routing()
    if operation == "get-config-vpn":
        return _vpn()
    if operation == "get-config-services":
        return _services()
    raise CollectionFailure("malformed_xml")


class FixtureTransport:
    def __init__(self, name: str) -> None:
        if name not in _NAMES:
            raise CollectionFailure("malformed_response")
        self.name = name
        self.starts = 0
        self.calls: list[str] = []
        self.reconnect_delays: list[float] = []

    def presented_fingerprint(self) -> str:
        return OTHER if self.name == "host-key-mismatch" else PIN

    def observed_at(self) -> datetime | None:
        if self.name == "stale":
            return datetime(2020, 1, 1, tzinfo=UTC)
        return None

    def start(self, configuration: dict) -> None:
        self.starts += 1
        if self.name == "timeout":
            raise CollectionFailure("connection_timeout")
        if self.name == "reconnect" and self.starts == 1:
            raise CollectionFailure("connection_timeout")
        if self.name == "auth-rejected":
            raise CollectionFailure("authentication_rejected")
        fingerprint = configuration.get("host_key_fingerprint")
        if self.name == "missing-host-key":
            host_key_accepted("", self.presented_fingerprint())
        elif fingerprint:
            host_key_accepted(str(fingerprint), self.presented_fingerprint())

    def rpc(self, operation: str) -> bytes:
        assert_allowed(operation)
        self.calls.append(operation)
        if self.name == "partial" and operation == "get-config-vpn":
            raise CollectionFailure("vendor_unavailable")
        return document(self.name, operation)


def configuration(fixture: str = "nordic-retail", device_id: str = DEVICE, fingerprint: str | None = PIN) -> dict:
    body: dict[str, str] = {"fixture": fixture, "device_id": device_id, "host_key_algorithm": "ssh-ed25519"}
    if fingerprint is not None:
        body["host_key_fingerprint"] = fingerprint
    return body
