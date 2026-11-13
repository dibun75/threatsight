# ADR 0015 — Informational framework coverage, never legal compliance

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M6 must make governance mappings useful: operators should see which controls relate to EU AI Act, GDPR, NIST AI RMF, ISO/IEC 42001, OWASP GenAI, and MITRE ATLAS topics, with source provenance. The product must not become a legal-compliance engine or claim that a test result proves an organization is compliant.

M1 already stored generic framework references. Those stubs were not a catalog and had no coverage view.

## Decision

- Ship a curated, incomplete catalog of framework *items* with public locators, a short informational statement, source kind, and catalog version. Do not store full legal or ISO text.
- Keep mappings informational. `legal_compliance_claim` is always false. `catalog_complete` is always false.
- Derive item coverage only from mapped controls' existing assurance statuses. Unmapped items are `EVIDENCE_REQUIRED`. Reject `COMPLIANT`.
- Bootstrap may map CTRL-002 to a small suggested set. Mapping never sets a legal label.

## Consequences

- Operators can explain "this control is referenced to this public topic" with a locator.
- Coverage numbers are real aggregates, not invented compliance scores.
- Expanding the catalog later does not require a new domain model, only new curated items.
