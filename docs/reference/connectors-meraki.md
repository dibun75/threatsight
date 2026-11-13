# Cisco Meraki Dashboard connector

Status: `fixture_tested`
Review date: 2026-10-30
API version reviewed: Dashboard API `v1.75.1` (documentation date 16 October 2026)

This adapter is a customer-resident, read-only collector on the existing connector SDK, secret-reference, runner, job, lease, cancellation, and kill-switch path. It has no separate execution path and no connector-specific secret table. No authorized Meraki organization was available. Pagination, permission errors, product availability, and real organization behavior still require a design partner. Nothing in this document is live verification.

## Official contract

| Topic | Record |
| --- | --- |
| Documentation | [Getting started](https://developer.cisco.com/meraki/api-v1/getting-started/), [Authentication](https://developer.cisco.com/meraki/api-v1/authorization/), [Pagination](https://developer.cisco.com/meraki/api-v1/pagination/), [Rate limit](https://developer.cisco.com/meraki/api-v1/rate-limit/) |
| Operations | [Organizations](https://developer.cisco.com/meraki/api-v1/getting-started/), [networks](https://developer.cisco.com/meraki/api-v1/get-organization-networks/), [devices](https://developer.cisco.com/meraki/api-v1/getting-started/), [device statuses](https://developer.cisco.com/meraki/api-v1/get-organization-devices-statuses/), [appliance uplink statuses](https://developer.cisco.com/meraki/api-v1/get-organization-appliance-uplink-statuses/), [VPN statuses](https://developer.cisco.com/meraki/api-v1/get-organization-appliance-vpn-statuses/), [network appliance VLANs](https://developer.cisco.com/meraki/api-v1/get-network-appliance-vlans/) |
| Base URI | `https://api.meraki.com/api/v1` only. Canada, China, India, and FedRAMP hosts are documented and are not enabled |
| Authentication | `Authorization: Bearer` with the API key, as documented for Dashboard API v1. The OpenAPI security scheme also lists `X-Cisco-Meraki-API-Key`; this connector sends only the bearer header. OAuth authorization-code tokens are not implemented |
| Pagination | RFC 5988 `Link` relations, which this connector parses as RFC 8288. Only `rel=next` is followed, and only when the scheme, host, port, path, and `perPage` stay on the same operation |
| Rate limit | 10 requests/second/organization, with a short burst, and 100 requests/second/source IP. HTTP 429 includes `Retry-After`. The connector records the delay and stops that collection. It does not sleep-and-retry a 429 |
| Minimum access | An organization read-only administrator, or OAuth scopes limited to the reads below. Write scopes are not required and are not used |

Documented OAuth scopes for the operations in use:

| Operation | Method and path | Scope |
| --- | --- | --- |
| List networks | `GET /organizations/{organizationId}/networks` | `dashboard:general:config:read` |
| VPN statuses | `GET /organizations/{organizationId}/appliance/vpn/statuses` | `sdwan:telemetry:read` |
| Appliance uplink statuses | `GET /organizations/{organizationId}/appliance/uplink/statuses` | `sdwan:telemetry:read` |
| Network VLANs | `GET /networks/{networkId}/appliance/vlans` | `sdwan:config:read` |

`GET /organizations` and `GET /organizations/{organizationId}/devices` are documented in the getting-started guide. `GET /organizations/{organizationId}/devices/statuses` is the documented device-status operation. Their OAuth scope was not printed on those pages; the working assumption is the same Dashboard read used for networks, via a read-only organization administrator when an API key is used. A design partner must confirm the key's role and any product entitlement before live collection.

Appliance VLAN, VPN, and uplink operations depend on MX, Z-series, or Secure Router availability. HTTP 400 or 404 on those reads becomes `unsupported` with `product_unavailable` or `permission_unavailable`. That is not an empty-and-safe result. The beta organization-wide VLAN operation is not called. `GET /devices/{serial}/managementInterface` is not called because it is a configuration document that can carry credentials; management addressing is taken from device status and appliance uplink status instead.

## Collection and minimization

The configured `organization_ids` are the only organizations that are collected. Organizations returned by the credential but absent from that list are counted and not stored. A configured organization that the credential cannot see is stored as `unknown` with `missing_or_inaccessible`.

Retained fields, and why:

| Field | Why it is retained |
| --- | --- |
| Organization id and sanitized name | Scope and site correlation. The name is sensitive operational metadata and is not an exposure conclusion |
| Network id, sanitized name, product types, time zone | Site boundary and which product families exist there |
| Device serial, model, firmware, product type, network id, LAN IP | Inventory, firmware, and topology membership. The serial is sensitive |
| Status, public IP, LAN IP, source `lastReportedAt` | Reachability metadata and freshness. A public address is sensitive and is not itself a finding |
| Uplink interface, status, IP, gateway, public IP, HA role | Appliance path and management-relevant addressing |
| VPN mode, exported subnets, Meraki peer network ids, third-party public IPs | Site-to-site participation without peer names |
| VLAN id, subnet, appliance IP | Subnet metadata for the appliance network |

A source timestamp older than the 30-day freshness window is `stale`. Collection time, connector, mode, contract, and limitations are stored on every record. Repeated collection of the same fixture is idempotent.

Deliberately excluded:

- Client and user traffic, packet captures, location analytics, and wireless client identities
- Event and syslog payloads, configuration backups, and custom property documents
- Tags, notes, street addresses, coordinates, MAC addresses, DNS server lists, DHCP assignments, enrollment strings, dashboard URLs, and VLAN or peer names
- API keys, authorization headers, secret-shaped values, email addresses, and raw response bodies
- Display names as a source of device role, exposure, privilege, or compromise

Switch membership is the device-to-network relationship already present on the device record. No wireless-client or extra switching endpoint is called.

## Safety controls

- Allow-listed GET requests only. POST, PUT, PATCH, and DELETE are rejected before a socket is opened.
- Ordinary configuration cannot set a base URL. A loopback test origin is accepted only when `THREATSIGHT_ENV` is `development` or `test`.
- Redirects are refused. `Link` targets that change scheme, host, port, path, or `perPage` are refused.
- Connect and read are bounded by a 20-second timeout. Vendor retries apply only to HTTP 500, 502, 503, and 504, at most three attempts, with a capped delay. HTTP 429 is not retried.
- Pages, records, response bytes, HTTP calls, and collection duration are bounded. Cancellation, lease ownership, and the kill switch are checked between pages and endpoint groups.
- An interrupted Meraki collection that already holds records is stored as partial. An expired lease stops without writing a completed result.
- Fixture mode remains `fixture_tested`. Clients cannot set `live_verified`.

## Live validation

Live collection is off unless the runner has `THREATSIGHT_MERAKI_LIVE=true`. The runner resolves `THREATSIGHT_MERAKI_CREDENTIALS` by the secret-reference locator and refuses placeholder or short keys before any request. The instance must name at least one organization id. A result is `live_verified` only after that opt-in collection finishes without truncation, rate limiting, or a rejected continuation. Ordinary tests do not set the flag. No live collection has been run.

## Security review

The fixture suite covers SSRF and redirect rejection, pagination-origin checks, API-key redaction, newline stripping, malicious identifiers, oversized and repeated pages, bounded retries, lease and cancellation races, unsafe address and subnet parsing, cross-tenant and cross-workspace rejection, raw-field omission, and rejection of write methods. Credential values are not placed in errors.

## Verification

On 2026-10-30 the isolated API suite passed 203 tests and skipped 1. Focused Meraki, Microsoft, connector, trust, and database-isolation tests passed 68. The preserved database stayed at revision `0013_connector_execution` with 2,182 threat events, 2,182 relevance rows, and 41 clusters. No test database was left behind. Ruff passed. No Python dependency was added, and mypy is not configured. The public API image was not rebuilt.
