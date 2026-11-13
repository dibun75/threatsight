# ADR 0016 — Informational threat intelligence, not an attack engine

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M7 must make new AI-security intelligence useful: operators should see which threats and techniques relate to their controls and which existing assurance tests are candidates. The product must not become a news aggregator, crawler, or exploitation engine, and must not claim legal compliance.

## Decision

- Ship a curated, incomplete catalog of threats, techniques, and advisories with public https locators and short informational statements. Do not store exploit procedures.
- Ingest is schema-validated catalog write. Locators are provenance, not fetch targets. Reject crawl/fetch/attack fields.
- Map techniques to existing controls informationally. Derive coverage from mapped control assurance statuses. Mapping and ingest never mutate `assurance_status`.
- Suggest existing CTRL-002 scenarios as candidate tests. Suggestions do not execute.
- Identify affected systems from mapped-control runs, evidence, findings, and the labelled demo system.

## Consequences

- Operators can answer "which controls and tests matter for this technique" with source locators.
- Expanding the catalog later does not require a crawl subsystem.
- News-firehose ingestion and trend maps remain out of scope.
