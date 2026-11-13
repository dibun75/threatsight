# Cisco Meraki live validation

Prerequisite: a design partner and written authorization for one organization. No Meraki API key is authorized.

## Before collection

- Connector key `meraki.dashboard`.
- Record runner and control-plane versions.
- Authorization names the organization id, the networks in scope, the window, and the approvers.
- The API key is read-only for the inventory endpoints the connector calls. It is a secret reference on the runner. It is not a dashboard administrator with write access.
- Allowlist is that organization. Expected records are the inventory fields in the fixture contract. Excluded: client traffic payloads, packet captures, and write configuration.
- Duration stays inside the job bounds. Stop on HTTP 429 after the retry cap, on kill switch, or on an organization id that was not authorized.
- Rollback deletes the key in Meraki and revokes the runner credential.

## Maturity

Use the ten conditions in [live-azure.md](./live-azure.md). A `200` from the dashboard is not `live_verified`. Rate-limit errors stay failed or partial. They are not rewritten as an empty network.
