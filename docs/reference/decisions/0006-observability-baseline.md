# ADR 0006 — Observability baseline

**Status:** Accepted  
**Date:** 2026-08-27

## Context

Operators need to know whether the skeleton is alive and which request failed. Full telemetry vendor integration is not M0.

## Decision

- JSON structured logs with request IDs.
- `/health` for liveness, `/ready` for Postgres.
- No APM vendor. No OTEL exporter yet.

## Consequences

- Compose healthchecks can gate `web` on `api`.
- Adding OpenTelemetry later should wrap the existing request-id context, not replace logs.
