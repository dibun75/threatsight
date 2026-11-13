# Connector SDK, Permissions, and Maturity

Phase 2 connector SDK `v1` is a read-only contract. Implementations may expose only bounded inventory, configuration-evidence, and health collection. Mutation, remediation, arbitrary commands, and inbound customer-network control are outside the contract.

## Contract

- Capabilities: `inventory`, `configuration_evidence`, `health`.
- Permissions: `inventory.read`, `configuration.read`, `identity.read`, `health.read`.
- Modes: `fixture` and opt-in `live`.
- Pages contain at most 500 normalized records; payloads are bounded to 64 KiB per normalized attributes/provenance object.
- Rate-limit responses carry a bounded retry delay. Unsupported capability is an explicit state, not an empty success.
- Every record has source identity, collection time, provenance, limitations, and an explicit truth state.
- Every result envelope carries SDK version, job ID, idempotency key, sequence, mode, maturity, and deterministic content hash.

## Maturity

| State | Meaning |
| --- | --- |
| `unsupported` | No implementation or the requested capability is unavailable. |
| `experimental` | Contract implementation exists but fixture acceptance is incomplete. |
| `fixture_tested` | Sanitized fixtures and bounded failure behavior pass. This is not vendor certification. |
| `live_verified` | Authorized live validation passed for a documented vendor/API/version scope. |

Maturity never promotes automatically. Fixture evidence cannot be labelled live verified.

## Secret and permission boundary

Connector rows store only a secret-manager/provider locator and optional version hint. Secret-shaped configuration, job input, and progress fields are rejected. Ordinary API output redacts locators, and request logs record method, path, and status only. Customer-runner references resolve locally. A runner claims only its own tenant and workspace, workspace claims are serialized, and an expired lease can be reclaimed until attempts are exhausted.

The Azure Resource Graph, Entra, Meraki, and Junos reference adapters are `fixture_tested`. Their permission, field, and retention records are [Azure and Entra connectors](./connectors-microsoft.md), [Meraki connector](./connectors-meraki.md), and [Junos connector](./connectors-junos.md). Fixture evidence is not live verification. Junos has no linked NETCONF client and is not live-verified.
