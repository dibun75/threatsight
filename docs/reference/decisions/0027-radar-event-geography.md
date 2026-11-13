# ADR 0027 — Explicit Radar event and geography semantics

## Status

Accepted for Phase 1.

## Context

Phase 0 used a single event-type string and `countries` list. That representation can conflate the reporting authority's jurisdiction with target, victim, infrastructure, or product-prevalence geography and can overstate incident or attribution claims.

## Decision

- Normalize events as `advisory`, `vulnerability`, `campaign`, `incident_report`, or `national_risk_level_change`.
- Store reporting-authority jurisdictions, target countries, victim countries, infrastructure countries, and vendor/product prevalence countries separately.
- Preserve source-provided confidence, provenance, limitations, parser version, payload hash, and canonical link.
- Treat missing geography as unknown. Never derive attacker origin from IP data or authority jurisdiction.
- Relevance may explain an authority-jurisdiction match, but it is weaker than a source-supported target-country match and is never exposure proof.
- Backfill Phase 0 country values as authority jurisdiction based on the source; do not silently relabel them as targets or victims.

## Consequences

Filters and UI labels must name the geographic role. Parsers must avoid inference when a source does not state a role. Legacy `countries` remains only for migration compatibility and is not the Phase 1 authority for geographic claims.
