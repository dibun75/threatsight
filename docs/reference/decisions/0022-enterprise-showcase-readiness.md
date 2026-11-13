# ADR 0022 — Enterprise showcase package without new capabilities

**Status:** Accepted  
**Date:** 2026-08-28

## Context

M12 must turn the completed product into a presenter package: a realistic company scenario, architecture diagrams, security bounds, and CV wording. Adding engines, dashboards, or legal claims would violate the milestone.

## Decision

- Frame the existing CTRL-002 **Order support demo** as Nordic Retail AS / Customer Support AI Assistant in showcase copy and documentation.
- Do not rename inventory records or add control families. Keep `labelled_synthetic` true and `legal_compliance_claim` false.
- Put presenter documents under `docs/showcase/`. Improve only confusing presentation on existing screens.

## Consequences

- Reviewers can tell the FAIL → evidence → remediate → retest story in minutes.
- The product still does not claim certification or live enterprise discovery.
