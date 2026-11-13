# ADR 0004 — Security baseline and kill switch

**Status:** Accepted  
**Date:** 2026-08-27

## Context

The assurance engine will eventually run authorized scenarios. Safety must exist before that engine exists, or it will be bolted on under schedule pressure.

## Decision

- Default sandbox on.
- Process-wide kill switch via configuration; future execution must honor it.
- Verdict evaluator is a closed set: `deterministic_policy` only.
- No scenario runner, exploit payloads, or external target client in M0.
- Security posture is inspectable at `/api/v1/security/status`.

## Consequences

- M3 cannot "just add attacks" without reading this ADR.
- Operators can fail a deployment closed without code changes (`THREATSIGHT_KILL_SWITCH=true`).
