# ADR 0033: Outbound runners and durable connector jobs

Status: Accepted

## Decision

Connector execution uses PostgreSQL-owned jobs and an outbound-only runner protocol. Secret values remain in customer or approved secret stores; ThreatSight persists tenant/workspace-owned metadata references only.

Runner registration issues a high-entropy credential once, stores only its SHA-256 hash, and supports expiry, rotation, and revocation. A runner may claim only work in its tenant/workspace and assigned runner scope. No runner service publishes an inbound host port.

Jobs are workspace-owned and idempotent. Claim uses row locking with skip-locked semantics, a bounded lease, per-workspace concurrency, and explicit attempts/audit. Failure uses bounded exponential backoff before terminal dead-letter state. Cancellation is durable and checked by progress/completion. The global kill switch is checked at enqueue, claim, and immediately before execution.

Connector SDK `v1` is read-only and supports bounded inventory, configuration evidence, and health. It separates fixture/live modes and unsupported/experimental/fixture-tested/live-verified maturity.

## Consequences

- A database outage pauses work without silently losing queue state.
- Expired leases can be reclaimed; duplicate requests return the existing workspace job.
- Runner compromise is constrained by credential lifetime, workspace assignment, revocation, and read-only adapters.
- This is a single-node reference implementation, not an HA queue or a production vendor certification.
