# ADR 0029 — Workspace-owned Radar workflow data

## Status

Accepted for Phase 1.

## Context

Saved views, triage, assignments, business services, readiness links, and their audit history contain organization-specific data. Legacy M0–M15 controls, evidence, AI systems, and audit rows are deployment-global and are not safe tenant boundaries.

## Decision

- Store saved views, triage, business services, readiness links, legacy-resource bindings, and Radar workflow audit records with a mandatory workspace ID.
- Resolve every route through authenticated subject plus workspace membership; operators/reviewers/admins may mutate and auditors remain read-only.
- Require a workspace relevance row before an event or cluster can receive workspace workflow data.
- Require an explicit workspace-resource binding before linking a legacy control, evidence record, or AI system.
- Return minimal target snapshots through Radar rather than treating legacy APIs as tenant scoped.
- Treat every readiness link as analyst context: `informational_only=true`, no exposure confirmation, no verdict effect, and no legal-compliance claim.
- Never mutate control status, evidence status, assurance runs, findings, or remediations through a Radar link.
- Keep Radar workflow audit history in a dedicated workspace-scoped table.

## Consequences

This isolates the Phase 1 Radar workflow surface, but it does not tenantize the legacy APIs or tables. Shared multi-customer deployment still requires legacy tenantization or deployment isolation and enterprise identity.
