# ADR 0030 — Consolidated Docker deployment

**Status:** Accepted  
**Date:** 2026-10-30

## Context

The shared host contained an obsolete `threatsight` deployment and the current Phase 1 deployment under `threatsight-2`. Duplicate identities made operations and tunnel routing ambiguous. The obsolete deployment and its data were explicitly authorized for permanent deletion.

## Decision

- The sole current Compose project is `threatsight`.
- Core containers and application images use explicit product names without Compose `-1` suffixes.
- Current resources carry exact Compose labels and `com.threatsight.generation=current`; cleanup uses explicit allow-lists rather than name-prefix matching.
- Phase 1 data was moved by verified custom-format `pg_dump`/`pg_restore` into `threatsight_postgres_data`; the obsolete database was not copied.
- Cloudflare attachment is optional through `docker-compose.tunnel.yml`, which joins only `threatsight-web` to external `infra_gateway`.
- Rollback retained the source volume and verified logical dump until revision, row-count, health, Radar, and public-origin checks passed. The old volume was then permanently deleted.

## Consequences

The current core runtime is unambiguous and remains isolated from shared-host infrastructure. Local installations do not require `infra_gateway`. The logical dump remains the disaster-recovery artifact; deleted obsolete volumes are not recoverable.

The Cloudflare Tunnel token exposed during earlier diagnostics must be rotated manually. Replacement token material must never be read, logged, stored, or committed by this repository.
