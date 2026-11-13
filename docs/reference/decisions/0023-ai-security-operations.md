# ADR 0023 — AI security operations without model authority

**Status:** Accepted  
**Date:** 2026-08-28

## Context

M13 must connect governance, assurance, discovery, and threat intelligence into an operations product: a provider-agnostic intelligence layer, an agent event contract, an operational threat chain, a question-first dashboard, a system risk view, and evidence-linked explanations.

LLMs are useful for summarization. They are not allowed to authorize tools, change PASS/FAIL, or declare legal compliance. The product must not become a SIEM, GRC suite, crawler, or runtime firewall.

## Decision

- Keep M2 document extraction as-is. Add sibling intelligence tasks behind `heuristic` / optional `openai` providers.
- Persist intelligence provenance (`provider`, `model`, `prompt_version`, `confidence`, `uncertainty`) without storing API keys.
- Ingest passive agent events (`http_assessment`, `gateway`, `sdk`, `otel`) scoped to an existing AI system. Do not enforce at ingest.
- Extend the curated threat catalog with AI-specific categories and `affected_capability`. Unauthorized tool execution remains mapped to CTRL-002. Catalog stays informational and incomplete.
- Rework the landing dashboard around six operations questions derived from persisted counts. Keep provenance folds.
- Extend system posture with profile, traces, threat exposure, tests, missing information, and UNKNOWN when facts are absent.
- Evidence-linked explain cites source records. Heuristic is the default. LLM output cannot change verdicts.

## Consequences

- Operators can tell the Nordic Retail story from inventory through CTRL-002 FAIL/PASS to an executive explanation without database internals.
- Tests mock LLM responses. Empty API keys fail closed to heuristic.
- Later live threat feeds, SSO, or runtime enforcement require a new ADR.
