# ADR 0018 — Deterministic showcase narrative and evidence freshness

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M9 must make the M0–M8 product demoable. Fake dashboard numbers, LLM-authored legal prose, or auto-executed attacks would look finished and be wrong.

## Decision

- Executive summary sentences are derived only from persisted counts. `llm_authored` is always false. `legal_compliance_claim` is always false.
- Evidence freshness is `FRESH`, `STALE`, or `UNTESTED` from real timestamps and a configured day window. It is not a score and never `COMPLIANT`.
- Showcase bootstrap chains existing labelled demos. AUTH-01 still requires `confirm_execution`. Discovery scans are not started by bootstrap.

## Consequences

- Reviewers can walk inventory → control → test → evidence without invented metrics.
- A stale control is an aging signal, not a legal finding.
- The showcase cannot be mistaken for an autonomous attack engine.
