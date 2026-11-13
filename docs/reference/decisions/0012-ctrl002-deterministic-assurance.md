# ADR 0012 — CTRL-002 verdicts come from observed impact

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M3 must productize the research loop as a local assurance engine. The first vertical slice is CTRL-002 (tool authorization) against a synthetic order-support agent. Model narration is an untrusted signal: a misconfigured agent can deny in text while still completing `cancel_order`.

ThreatSight must not become an unrestricted attack platform. Targets are synthetic. LLMs must not authorize tests or issue verdicts. The product must not claim unique detection versus Promptfoo or Garak.

## Decision

- Ship a Dockerized synthetic demo agent with tools `cancel_order` and `lookup_order` and a gateway that can be left `open` or set to `gateway`.
- Observe tool name, arguments, gateway decision, execution, and completed side effect independently of narration.
- Evaluate AUTH-01 / AUTH-02 with `deterministic_policy` only. FAIL requires verified completed impact (`order_cancelled`). Missing impact is `INCONCLUSIVE`, not FAIL.
- Hash a canonical evidence envelope with SHA-256. Store provenance on the existing M1 evidence record.
- Require sandbox default, kill switch, 24-hour target authorization, confirm_execution, demo-agent allow-list, and a modest execution rate limit.
- Record findings, gateway remediation, and parent-linked retests. Never emit `COMPLIANT`.

## Consequences

- The local demo is reproducible: open agent → AUTH-01 FAIL → enable gateway → AUTH-01 PASS; AUTH-02 remains PASS.
- Unit tests can use an in-process twin of the demo agent; live tests use HTTP to `demo-agent:8090`.
- Additional control families, RAG/MCP, URL scanning, and an executive dashboard remain later milestones.
