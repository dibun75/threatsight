"""Sanitized synthetic Meraki inventory for the fictional Nordic Retail scenario.

Identifiers, names, and addresses are invented. Nothing here is a copied
production response.
"""

from __future__ import annotations

from threatsight_api.connectors.meraki.bounds import ORIGIN, PAGE_SIZE
from threatsight_api.connectors.meraki.transport import VendorRequest, VendorResponse

ORG_HQ = "900000001"
ORG_BRANCH = "900000002"
ORG_UNSELECTED = "900000003"
ORG_MISSING = "900000004"
NET_HQ = "L_900000001001"
NET_EMPTY = "L_900000001002"
NET_BRANCH = "L_900000002001"
NET_DANGLING = "L_900000009999"
EDGE = "SYN0-0000-0001"
SWITCH = "SYN0-0000-0002"
BRANCH_EDGE = "SYN0-0000-0003"
PUBLIC_HQ = "203.0.113.10"
PUBLIC_BRANCH = "203.0.113.20"


def configuration(fixture: str = "nordic-retail", organization_ids: list[str] | None = None) -> dict:
    selected = organization_ids or [ORG_HQ, ORG_BRANCH]
    return {"fixture": fixture, "organization_ids": selected}


def _next(path: str, token: str) -> str:
    return f'<{ORIGIN}/api/v1{path}?perPage={PAGE_SIZE}&startingAfter={token}>; rel="next"'


class FixtureTransport:
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[str] = []
        self._attempts = 0

    def send_once(self, request: VendorRequest, token: str) -> VendorResponse:
        del token
        self.calls.append(request.url)
        self._attempts += 1
        if request.method != "GET":
            return VendorResponse(405, {})
        if self.name == "forbidden":
            return VendorResponse(403, {}, {"errors": ["denied"]})
        if self.name == "redirect":
            return VendorResponse(302, {"location": "https://evil.example/collect"}, None)
        if self.name == "malformed":
            return VendorResponse(200, {}, malformed=True)
        if self.name == "oversized":
            return VendorResponse(200, {}, byte_length=1_048_577)
        if self.name == "transient" and self._attempts == 1:
            return VendorResponse(503, {}, {"errors": ["temporary"]})
        if self.name == "throttled":
            return VendorResponse(429, {"retry-after": "2"}, {"errors": ["API rate limit exceeded for organization"]})
        path = request.url.split("?", 1)[0].removeprefix(f"{ORIGIN}/api/v1")
        return self._body(path, request.url)

    def _body(self, path: str, url: str) -> VendorResponse:
        if path == "/organizations":
            return self._organizations()
        if path.endswith("/networks"):
            return self._networks(path, url)
        if path.endswith("/devices/statuses"):
            return self._optional(self._statuses(path), missing=self.name == "missing-optional")
        if path.endswith("/appliance/uplink/statuses"):
            return self._uplinks(path)
        if path.endswith("/appliance/vpn/statuses"):
            if self.name == "license":
                return VendorResponse(400, {}, {"errors": ["appliance product is not available"]})
            return self._vpn(path)
        if path.endswith("/devices"):
            if self.name == "partial":
                return VendorResponse(429, {"retry-after": "2"}, {"errors": ["API rate limit exceeded for organization"]})
            return self._devices(path)
        if "/appliance/vlans" in path:
            return self._vlans(path)
        return VendorResponse(404, {}, {"errors": ["unsupported"]})

    def _organizations(self) -> VendorResponse:
        if self.name == "malicious-link":
            return VendorResponse(200, {"link": "<https://evil.example/api/v1/organizations>; rel=\"next\""}, [
                {"id": ORG_HQ, "name": "Synthetic headquarters"},
            ])
        if self.name == "excessive":
            return VendorResponse(200, {"link": _next("/organizations", "900000001")}, [
                {"id": ORG_HQ, "name": "Synthetic headquarters"},
            ])
        rows = [
            {"id": ORG_HQ, "name": "Synthetic headquarters\nINJECT", "apiKey": "secret-shaped-value"},
            {"id": ORG_BRANCH, "name": "Synthetic branch"},
            {"id": ORG_UNSELECTED, "name": "Synthetic unselected", "url": "https://evil.example/org"},
        ]
        if self.name == "empty":
            rows = [{"id": ORG_HQ, "name": "Synthetic empty organization"}]
        return VendorResponse(200, {}, rows)

    def _networks(self, path: str, url: str) -> VendorResponse:
        org = path.split("/")[2]
        if self.name in {"empty", "empty-network"} and org == ORG_HQ and self.name == "empty":
            return VendorResponse(200, {}, [])
        if self.name == "paged" and org == ORG_HQ:
            if "startingAfter" not in url:
                return VendorResponse(200, {"link": _next(f"/organizations/{ORG_HQ}/networks", NET_HQ)}, [
                    self._network(NET_HQ, ORG_HQ, "Synthetic headquarters", ["appliance", "switch"]),
                ])
            return VendorResponse(200, {}, [self._network(NET_EMPTY, ORG_HQ, "Synthetic empty network", ["switch"])])
        rows = []
        if org == ORG_HQ and self.name != "empty":
            rows.append(self._network(NET_HQ, ORG_HQ, "Synthetic headquarters", ["appliance", "switch"]))
            if self.name == "empty-network":
                rows = [self._network(NET_EMPTY, ORG_HQ, "Synthetic empty network", ["switch"])]
            elif self.name not in {"paged"}:
                rows.append(self._network(NET_EMPTY, ORG_HQ, "Synthetic empty network", ["switch"]))
        if org == ORG_BRANCH and self.name not in {"empty", "empty-network", "paged"}:
            rows.append(self._network(NET_BRANCH, ORG_BRANCH, "Synthetic branch", ["appliance"]))
        return VendorResponse(200, {}, rows)

    def _network(self, network_id: str, org: str, name: str, products: list[str]) -> dict:
        return {
            "id": network_id,
            "organizationId": org,
            "name": name,
            "productTypes": products,
            "timeZone": "Europe/Oslo",
            "tags": ["ignore-me", "Bearer secret"],
            "notes": "free text that must not be retained",
            "url": "https://dashboard.example/network",
            "enrollmentString": "person@example.com",
        }

    def _devices(self, path: str) -> VendorResponse:
        org = path.split("/")[2]
        if self.name in {"empty", "empty-network"}:
            return VendorResponse(200, {}, [])
        rows = []
        if org == ORG_HQ:
            edge = {
                "serial": EDGE, "model": "MX-SYN", "firmware": "appliance-0.0", "productType": "appliance",
                "networkId": NET_DANGLING if self.name == "dangling" else NET_HQ, "lanIp": "10.8.0.1",
                "name": "edge display name", "mac": "00:00:00:00:00:01", "notes": "api_key=secret-shaped-value",
                "address": "Example Street 1", "lat": 59.9, "lng": 10.7, "tags": ["wan"],
            }
            switch = {
                "serial": SWITCH, "model": "MS-SYN", "firmware": "switch-0.0", "productType": "switch",
                "networkId": NET_HQ, "lanIp": "999.1.1.1" if self.name == "invalid-subnet" else "10.8.0.2",
            }
            rows.extend([edge, switch])
            if self.name == "duplicates":
                rows.append(dict(edge))
            if self.name == "conflicting":
                other = dict(edge)
                other["firmware"] = "appliance-9.9"
                rows.append(other)
        if org == ORG_BRANCH:
            rows.append({
                "serial": BRANCH_EDGE, "model": "MX-SYN", "firmware": "appliance-0.0", "productType": "appliance",
                "networkId": NET_BRANCH, "lanIp": "10.9.0.1",
            })
        return VendorResponse(200, {}, rows)

    def _statuses(self, path: str) -> VendorResponse:
        org = path.split("/")[2]
        reported = "2020-01-01T00:00:00Z" if self.name == "stale" else "2026-10-30T12:00:00Z"
        rows = []
        if org == ORG_HQ and self.name not in {"empty", "empty-network"}:
            rows.append({
                "serial": EDGE, "networkId": NET_HQ, "status": "online", "productType": "appliance",
                "publicIp": "not-an-ip" if self.name == "invalid-subnet" else PUBLIC_HQ,
                "lanIp": "10.8.0.1", "lastReportedAt": reported, "primaryDns": "198.51.100.1",
                "name": "edge display name", "mac": "00:00:00:00:00:01",
            })
        return VendorResponse(200, {}, rows)

    def _uplinks(self, path: str) -> VendorResponse:
        if ORG_HQ not in path or self.name in {"empty", "empty-network"}:
            return VendorResponse(200, {}, [])
        return VendorResponse(200, {}, [{
            "networkId": NET_HQ, "serial": EDGE, "model": "MX-SYN",
            "lastReportedAt": "2020-01-01T00:00:00Z" if self.name == "stale" else "2026-10-30T12:00:00Z",
            "highAvailability": {"enabled": False, "role": "primary"},
            "uplinks": [{
                "interface": "wan1", "status": "active", "ip": PUBLIC_HQ, "gateway": "203.0.113.1",
                "publicIp": PUBLIC_HQ, "primaryDns": "198.51.100.1", "secondaryDns": "198.51.100.2",
            }],
        }])

    def _vpn(self, path: str) -> VendorResponse:
        if ORG_HQ not in path or self.name in {"empty", "empty-network"}:
            return VendorResponse(200, {}, [])
        return VendorResponse(200, {}, [{
            "networkId": NET_HQ, "networkName": "Synthetic headquarters", "deviceSerial": EDGE,
            "deviceStatus": "online", "vpnMode": "hub",
            "exportedSubnets": [{"subnet": "not-a-cidr" if self.name == "invalid-subnet" else "10.8.0.0/24", "name": "ignore"}],
            "merakiVpnPeers": [{"networkId": NET_BRANCH, "networkName": "Synthetic branch", "reachability": "reachable"}],
            "thirdPartyVpnPeers": [{"name": "person@example.com", "publicIp": "198.51.100.50"}],
            "uplinks": [{"interface": "wan1", "publicIp": PUBLIC_HQ}],
        }])

    def _vlans(self, path: str) -> VendorResponse:
        if NET_HQ not in path:
            return VendorResponse(200, {}, [])
        return VendorResponse(200, {}, [{
            "id": "10",
            "name": "ignore-me",
            "subnet": "not-a-cidr" if self.name == "invalid-subnet" else "10.8.0.0/24",
            "applianceIp": "10.8.0.1",
            "fixedIpAssignments": {"00:00:00:00:00:09": {"ip": "10.8.0.9", "name": "person@example.com"}},
            "dhcpBootFilename": "secret-shaped-value",
            "dnsNameservers": "198.51.100.1",
        }])

    def _optional(self, response: VendorResponse, *, missing: bool) -> VendorResponse:
        if missing:
            return VendorResponse(404, {}, {"errors": ["optional product is not available"]})
        return response
