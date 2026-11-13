# ADR 0002 — Monorepo and runtime stack

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M0 needs a runnable local product skeleton: a documented API, a new UI, and Postgres.

## Decision

- Single repository with `apps/api` and `apps/web`.
- API: Python 3.12, FastAPI, SQLAlchemy, Alembic, psycopg3.
- Web: Next.js App Router, React, TypeScript.
- Data: Postgres 16.
- Compose is the development (and later self-host) entry point.

Python is used for the assurance/domain service because the deterministic control engine and evidence handling will live there. TypeScript is used for the UI only.

## Consequences

- One compose file runs the showcase locally.
- Domain types in Python are canonical; the UI consumes API JSON rather than owning the model.
- Additional engines may become services later without abandoning this layout.
