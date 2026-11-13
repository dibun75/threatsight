# ADR 0031: Preserve claim strength across control-plane and runner boundaries

Status: Accepted

## Decision

Phase 2 uses the fixed truth vocabulary in `PHASE-2-THREAT-MODEL.md`. Relationships retain provenance as observed, configured, inferred, or manual; maturity is synthetic, fixture-tested, or live-verified; incomplete evidence remains partial, stale, unknown, conflicting, or unsupported.

The customer-resident runner is an outbound-only, read-only boundary. Credentials and raw configurations remain local by default. The control plane receives minimized normalized records, provenance, timestamps, limitations, and evidence hashes. It never upgrades claim strength based on transport success or record presence.

## Consequences

Future connector, graph, path, match, finding, API, UI, and export schemas must represent these states explicitly. Missing evidence cannot produce a safe conclusion. Runner registration, secret storage, and durable jobs remain P2-05/P2-06 and must satisfy this decision.
