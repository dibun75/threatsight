# ADR 0013 — Dashboard aggregates only persisted assurance data

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M4 must present executive posture without inventing coverage numbers or legal conclusions. The product already has systems, controls, findings, runs, and documents.

## Decision

- Serve `GET /api/v1/dashboard` as a read-only aggregation over existing tables.
- Show all six assurance statuses, including zeros. Never `COMPLIANT`.
- Label the M3 order-support demo as synthetic when present.
- Keep M1–M3 write APIs unchanged except for additive list filters and a system posture read model.

## Consequences

- Empty environments show zeros, not placeholder charts.
- The UI can drill from posture to finding to evidence using real IDs.
- Coverage beyond CTRL-002 remains unproven and is not implied by the dashboard.
