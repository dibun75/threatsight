# ADR 0017 — Internal enterprise package without SSO or a GRC product

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M8 must make ThreatSight deployable inside an enterprise: Docker, secrets, backup, health, audit, and a stable API. Full SSO, a user directory, and live GRC connectors would be large products of their own. The prompt forbids billing, SaaS multi-tenancy, a marketplace, a generic GRC replacement, and production attack execution.

## Decision

- Keep the lab Compose stack as the default. Add an overlay (`docker-compose.enterprise.yml`) that drops demo sidecars, unpublishes Postgres, and uses in-process adapters.
- Add a shared API token (`THREATSIGHT_API_TOKEN`) that, when set, is required on `/api/*`. Lab mode with an empty token remains open for local tests.
- Authorize writes with `X-Role`. `auditor` is read-only. This is not SSO.
- Export JSON/CSV plus a versioned GRC exchange bundle. Do not build a live connector.
- Document OpenAPI (`/openapi.json`) as the stable API. Disable the docs UI in the enterprise overlay by default.
- Provide `make backup` / restore-with-`--yes`, an ops checklist, and GitHub Actions for isolated tests plus compose config.

## Consequences

- An internal team can run the product behind their own reverse proxy and identity-aware gateway.
- Adding OIDC later does not require replacing exports or the overlay.
- Operators must not treat lab-open mode as production.
