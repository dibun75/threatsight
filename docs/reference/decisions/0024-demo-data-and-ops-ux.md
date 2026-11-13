# ADR 0024 — Demo-data origin and operations UX truthfulness

**Status:** Accepted  
**Date:** 2026-08-28

## Context

M13 connected governance, assurance, and intelligence into an operations product, but the live lab dashboard mixed CI/test agents with the Nordic Retail story, repeated the same counts, and presented catalogued threats as if they were operationally tested. Inventory name **Order support demo** conflicted with presenter copy **Customer Support AI Assistant**.

M14 is a UX and demo-data milestone. It must not add attack classes, live feeds, legal scoring, or runtime enforcement.

## Decision

- Keep `Order support demo` as the unique database name. Present **Customer Support AI Assistant** / **Nordic Retail AS** as display identity; show the inventory name as a technical identifier.
- Persist `record_origin` on AI systems. API create always sets `manual`. Showcase bootstrap labels `showcase`. Clients cannot self-assign showcase origin.
- Default Overview aggregates `showcase` rows when any exist; `scope=all` remains available. Document-candidate queues are excluded from the showcase action list.
- Showcase reset deletes only `record_origin=showcase` systems and labelled showcase evidence, then may reseed. It does not mutate unlabelled records.
- Threat landscape states are Tested, Mapped, Catalogued, and Not yet assessed. Only existing CTRL-002 evidence may produce PASS/FAIL exposure.
- System posture uses ATTENTION REQUIRED / REVIEW REQUIRED / NO TESTED GAPS / NOT ASSESSED. Never `COMPLIANT`.
- Explain copy must not advertise LLM authorship when the heuristic path ran.

## Consequences

- A clean Nordic Retail journey is the default Overview. Test pollution remains in `/systems?` and `scope=all` but does not dominate first-run operations.
- Later multi-tenant origin policies or automated test-origin labelling require a new ADR.
