# Threat Intelligence

**Status:** M15 — curated informational catalog with evidence-state presentation. Only `tool_abuse` is marked tested from CTRL-002.

ThreatSight intelligence maps:

```text
Threat → Technique → AI System → Control → Test → Finding → Remediation → Retest
```

Evidence state is **Tested**, **Mapped**, **Catalogued**, or **Not yet assessed**. Catalogued is not tested. Only existing CTRL-002 evidence may produce PASS/FAIL exposure.

It is not a generic security-news globe, unrestricted crawl, or exploitation engine.

## Objects

- **Threat** — category such as prompt injection or tool abuse.
- **Technique** — normalized item with a public locator, source kind, and catalog version.
- **Advisory** — curated ingest record with provenance. Ingest does not fetch the locator.
- **Control mapping** — informational. Does not change `assurance_status`.
- **Candidate test** — pointer to an existing catalog scenario (AUTH-01 / AUTH-02). Never auto-executes.

Coverage of a mapped technique uses the same assurance vocabulary as M6. Unmapped techniques are `EVIDENCE_REQUIRED`. Never `COMPLIANT`.

The catalog is incomplete. An LLM is not the intelligence authority.
## Phase 0 Threat & Readiness Radar

The Radar adds a separate, normalized source pipeline. It does not replace the curated AI-threat catalog above.

Authoritative sources:

- CISA Known Exploited Vulnerabilities JSON.
- Norwegian NSM vulnerability-advisory RSS.
- FIRST EPSS API enrichment for CVEs already present in an ingested event.

Every source URL is fixed in code, HTTPS-only, size-limited, content-type checked, and redirect constrained. Synchronization is a manual write action. Records preserve source and external IDs, canonical URL, publication/source-update/ingest times, SHA-256 content hash, confidence, affected tags, CVEs, and source attributes. Reingestion updates the same source/external identity rather than creating duplicates.

Public events are global. Organization profiles and relevance assessments are workspace-scoped. Radar routes require authenticated subject membership and return events only through the selected workspace's relevance join.

The deterministic score explains country, sector, vendor, product, and technology matches, plus CISA active-exploitation and EPSS signals. It is a prioritization aid only:

- relevance is not confirmed asset exposure;
- geography is not attacker attribution;
- an event never changes PASS/FAIL or compliance state;
- exposure and readiness require inventory evidence and authorized control validation.

The `/radar` interface intentionally uses a calm paper/ink operational design and a decision queue. It does not use a decorative attack map or synthetic “AI” neon treatment.
