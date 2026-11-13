# ADR 0003 — Domain contracts before persistence

**Status:** Accepted  
**Date:** 2026-08-27

## Context

The control/governance data model is the product. Implementing full CRUD in M0 would smuggle M1 into the foundation.

## Decision

Encode the assurance vocabulary as Pydantic domain types in the API in M0. Persist only `app_metadata` needed for migrations and readiness. Product tables (systems, requirements, controls, evidence) wait for M1.

## Consequences

- Later milestones extend a named model (`Verdict`, `Control`, `EvidenceEnvelope`, …).
- M0 Docker is honest: it runs, but it is not a fake control registry.
- Schema migrations start with Alembic so M1 does not invent a second migration tool.
