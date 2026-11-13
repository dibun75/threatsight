# ADR 0036: Accountable action and evidence closure

Status: Accepted for Phase 3B reference implementation

## Context

Phase 3A produces verification recommendations, approved fixture-tested results, and human decisions. Enterprise accountability still needs ownership, closure requirements, reopen-on-change, and an unsigned evidence manifest. Findings lack tenant/workspace foreign keys and cannot enforce readiness relationships safely.

## Decision

Introduce workspace-scoped `readiness_actions` linked to readiness objects. Do not invent a general ticketing product. Do not overload unscoped findings.

### Lifecycle

`open` → `assigned` → `in_progress` → `awaiting_evidence` → `ready_for_review` → `closed`

Also: `reopened`, `superseded`, `cancelled`.

Permitted transitions (admin/operator as noted):

| From | To | Who |
| --- | --- | --- |
| open | assigned | operator+ |
| assigned | in_progress / awaiting_evidence / unassigned→open | operator+ |
| in_progress | awaiting_evidence / ready_for_review | operator+ |
| awaiting_evidence | ready_for_review / in_progress | operator+ |
| ready_for_review | closed / awaiting_evidence | workspace-admin+ for close |
| closed | reopened | workspace-admin+ or evidence-change engine |
| * | cancelled / superseded | workspace-admin+ |

Closure requires all mandatory requirements satisfied, authorized reviewer, outcome, rationale, evidence-hash snapshot. Outcomes: `resolved_by_evidence`, `remediation_completed`, `not_applicable`, `risk_accepted`, `superseded`.

### Ownership

Owners reference `identities.id` that hold active `workspace_memberships` in the same workspace, or unassigned. Assignment history is append-only. Removed members leave actions visibly orphaned.

### Evidence manifest

Canonical JSON + SHA-256 digest. Called “Evidence manifest” / “Integrity digest”. Never “signed”, “attestation”, or “certification”.

## Consequences

- Continuous readiness can demonstrate accountable closure without external ticketing.
- Later Phase 3C may sign the digest without changing manifest semantics.
- Commercial Phase 3, live connectors, and autonomous remediation remain out of scope.
