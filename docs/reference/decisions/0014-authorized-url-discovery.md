# ADR 0014 — Authorized allow-listed discovery, not a scanner

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M5 must help an organization discover AI exposure from a public source and map extracted statements into the assurance model. The 1.x product was a scanner. ThreatSight 2 must not resurrect unrestricted crawling, exploitation, or generic AppSec scanning. Public HTML is untrusted. An LLM must not authorize network fetch or treat extracted text as a verdict.

## Decision

- Ship a Dockerized synthetic demo site (`demo-site:8091`), unpublished on the host, as the only default fetch target.
- Register URLs only when the host is on the discovery allow-list derived from `THREATSIGHT_DEMO_SITE_URL`. Reject IP literals, credentials, and non-http(s) schemes.
- Require sandbox default, kill switch, 24-hour source authorization, `confirm_execution`, robots.txt, size/page caps, and a modest fetch rate limit.
- Extract signals with a deterministic HTML heuristic. Persist them as candidates with source URL, timestamp, quote, and content hash. Human approval materializes M1 evidence. Mapping to a control is optional and informational.
- Isolated tests use an in-process HTML twin. Live tests fetch `demo-site` on the Compose network.
- Never emit `COMPLIANT`. Never treat model output as fetch authority.

## Consequences

- The demo is reproducible: bootstrap → confirmed scan → reviewable signals → approved evidence with provenance.
- Operators cannot point discovery at arbitrary internet hosts in the default configuration.
- Broader URL ingestion, multi-host allow-lists, and framework productization remain later work.
