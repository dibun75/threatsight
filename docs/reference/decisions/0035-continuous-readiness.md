# ADR 0035: Threat-triggered continuous readiness

Status: Accepted for Phase 3A reference implementation

## Context

ThreatSight already connects global observations and synthetic technology matches to business services, configured controls, actions, and evidence. The missing enterprise differentiator is a bounded, approve-then-execute verification workflow when threat evidence changes.

## Decision

Phase 3A introduces workspace-scoped readiness objects that sit above the existing connector-job and evidence planes:

1. **Trigger** — a provenance-linked reason to consider revalidation. Global observation alone never creates a trigger.
2. **Recommendation** — a bounded suggestion that a specific control or evidence item may require validation. States: `candidate`, `needs_more_data`, `not_supported`, `superseded`, `dismissed`, `approved`.
3. **Verification request** — an approved or pending request for an allowlisted check. Types: read-only connector verification, manual evidence request, unsupported/live-validation-required.
4. **Execution** — a durable `connector_jobs` row. States remain queued, leased, running, succeeded, failed, cancelled, dead-letter, expired.
5. **Result** — a normalized outcome: `observed`, `configured_not_observed`, `passed_by_defined_check`, `failed_by_defined_check`, `unknown`, `conflicting`, `unsupported`, `collection_failed`. Generic `passed` is forbidden.
6. **Decision** — a human review: `accepted`, `remediation_required`, `not_applicable`, `needs_more_data`, `risk_accepted`, `superseded`.

Default policy is `manual_approval_required`. Autonomous execution is modelled but disabled.

A deterministic ruleset recommends verification only when there is a defensible chain:

Threat/advisory → technology or identifier match → business-service membership → relevant control or missing control evidence.

Execution reuses runner registration, leases, kill switch, idempotency, and result sanitization from ADR 0033. Secret values never leave the runner. The central API never opens a customer-network connection.

## What each state does not mean

- A recommendation is not a control failure.
- A successful collection is not control effectiveness.
- A failed verification is not compromise.
- `configured_not_observed` is not packet delivery or privilege effectiveness.
- `risk_accepted` records an operator choice. It is not compliance certification.

## Threat model (Phase 3A controls)

| Threat | Control |
| --- | --- |
| Malicious advisory mass jobs | Bounded fan-out; manual approval; no auto-exec from global observation |
| Cross-tenant trigger poisoning | Tenant/workspace ownership on every object; uniform not-found |
| Connector-result replay / evidence substitution | Evidence hashes; immutable provenance; sanitized results |
| Stale snapshot execution | Snapshot and correlation references; stale policy rejection |
| Secret-reference leakage | Runner-local locators only; never return secret values |
| Runner impersonation / duplicate jobs | Existing runner auth, leases, idempotency keys |
| Approval bypass | RBAC (`workspace-admin` / `platform-admin` / `admin`); CSRF for browser writes |
| Privilege escalation via manual actions | Operators may preview; approval roles enforced |
| Oversized results / raw transcripts | Payload limits; result sanitization; no transcripts stored |
| Job storms / kill-switch bypass | Per-workspace concurrency and kill switch checked at approve |
| Cancellation races / conflicting results | Last completed result preserved; supersession links |
| Unsupported write RPC | Allowlisted read-only check catalog only |
| Central API customer-network access | Fixture-tested in-process execution in Phase 3A; no device connect |

## Consequences

- Continuous readiness can be tested with synthetic reference journeys without claiming live customer validation.
- Approval, audit, supersession, and last-known-good evidence remain inspectable.
- Live connectors can later replace fixture-tested checks without changing the decision vocabulary.
