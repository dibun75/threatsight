# ADR 0026 — Global intelligence, workspace-scoped relevance

## Status

Accepted for the Phase 0 Radar vertical slice.

## Context

Authoritative advisories are public and identical for every customer, while organization profiles, relevance decisions, action ownership, and later exposure evidence are tenant data. Copying the full feed into every tenant creates duplicate provenance and difficult updates. Returning global events without a workspace join creates a cross-tenant disclosure risk.

The existing M0–M15 governance and assurance tables predate multi-tenancy. Retrofitting all of them in this slice would be a broad, high-risk migration.

## Decision

- Store normalized source and threat-event records globally.
- Preserve source identity, canonical locator, source and ingest timestamps, content hash, confidence, affected tags, CVEs, and source attributes.
- Store organization profiles and relevance assessments with a mandatory workspace ID.
- Resolve every Radar request through an authenticated subject plus workspace membership.
- Return events only by joining through that workspace's relevance records.
- Use a deterministic, explainable score; the LLM is not a relevance, exposure, or verdict authority.
- Keep CISA KEV, NSM RSS, and FIRST EPSS URLs fixed in code. Redirects must remain on the exact allow-listed HTTPS endpoint.
- Require a write-capable workspace role for profile changes and manual source synchronization.
- Treat relevance as informational. It neither confirms asset exposure nor changes an assurance verdict.
- State explicitly in the API that legacy M0–M15 tables are not tenant-scoped.

## Consequences

The Radar surface has enforceable workspace isolation and can reuse one authoritative feed safely. Cross-workspace read/write tests are required. Future asset, control-action, and evidence records must carry workspace IDs and use the same request boundary.

This is not complete enterprise multi-tenancy or SSO. Before multiple customer organizations share a deployment, the legacy data surface must be migrated or isolated by deployment, and the shared deployment token must be replaced by OIDC/SAML identities and group-to-workspace membership provisioning.
