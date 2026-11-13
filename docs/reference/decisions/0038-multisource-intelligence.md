# ADR 0038 — Multi-source exploitation intelligence

## Status

Accepted for Phase 3D reference implementation.

## Context

ThreatSight already stores CISA KEV and FIRST EPSS as separate dated facts. Operators also need vendor advisories, researcher exploitation observations, and media discovery without collapsing them into one opaque score or a news feed.

## Decision

Four source roles:

| Role | Authority | May set |
| --- | --- | --- |
| `vendor_authority` | Vendor PSIRT / ProductCERT | product/version/prerequisite/remediation; `vendor_confirmed` |
| `government_authority` | CISA KEV, national CERTs | `government_catalogued` (dated) |
| `exploitation_observation` | VulnCheck and approved research | `exploitation_reported` / `exploitation_directly_observed` |
| `media_discovery` | Allowlisted security publications | discovery metadata only; never `vendor_confirmed` or `government_catalogued` |

Evidence is stored as source documents and typed assertions. Assertions cluster by strong identifiers (CVE, vendor advisory ID, order/model numbers). Clusters retain disagreement.

Displayed exploitation vocabulary:

`not_reported` · `media_reported` · `researcher_observed` · `vendor_confirmed` · `government_catalogued` · `conflicting` · `withdrawn` · `unknown`

Multiple assertions may be simultaneous. Derivation is transparent and explained.

## Initial collectors

- Siemens ProductCERT CSAF (`vendor_authority`) — enabled when reachable.
- VulnCheck KEV Community API (`exploitation_observation`) — default disabled until a worker-only token file exists; requires prominent VulnCheck attribution.
- The Hacker News official RSS (`media_discovery`) — metadata and bounded excerpt only; no full article bodies.

## Consequences

- News is discovery, not vulnerability truth.
- Material changes may open Phase 3A readiness recommendations only when an organization-relevance chain exists.
- Signing (Phase 3C) may cover normalized hashes; it does not prove external reports are true.
- Absence from CISA KEV is not proof of no exploitation.
