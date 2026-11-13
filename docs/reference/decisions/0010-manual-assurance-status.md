# ADR 0010 — Manual assurance status in M1

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M1 needs a retrievable assurance status with provenance. Technical PASS/FAIL/INCONCLUSIVE verdicts belong to the later execution engine. Legal "compliant" claims are forbidden.

## Decision

- Store a **manual** assurance status on the control: `VALIDATED`, `PARTIALLY_VALIDATED`, `GAP_DETECTED`, `EVIDENCE_REQUIRED`, `HUMAN_REVIEW_REQUIRED`, `NOT_APPLICABLE`.
- Record who set it and why.
- Keep technical `Verdict` unused until M3.
- Framework mappings are informational (`legal_compliance_claim` is always false).
- Mutations append to `audit_events`; reviews are a separate append-only table.

## Consequences

- Operators can explain current control state before any attack loop exists.
- M3 must not silently overwrite manual status with an LLM opinion.
