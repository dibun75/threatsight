# ADR 0025 — Product UX consistency without new capabilities

## Status

Accepted for M15.

## Context

M14 made ThreatSight look like a security-operations product, but the acceptance walkthrough found ten consistency defects: mixed inventory on list pages, leftover FAIL/`GAP_DETECTED` after a PASS retest, eight always-clickable journey chips, AUTH-01 labelled as the retest, UUID evidence links, and a CISO-unusable nav.

## Decision

M15 is a presentation and scoping increment on existing records and engines.

- Showcase scope is an optional list filter. Persistence and default APIs stay unchanged (`scope=all` unless requested).
- Hero posture uses open finding status and latest technical verdict. `GAP_DETECTED` remains the stored assurance enum.
- AUTH-02 is the operator-facing retest name. Deterministic CTRL-002 rules are unchanged: AUTH-02 without a parent does not close a finding; `VALIDATED` still requires AUTH-01 with a parent.
- Proven landscape state `tested` is limited to `tool_abuse`.
- Navigation and copy changes do not add routes with new product capabilities. Dead aliases redirect.

## Consequences

- Operators can complete AUTH-01 → gateway → AUTH-02 without seeing a second “enterprise system” named Order support demo.
- Reviewers must not read AUTH-02 PASS as legal compliance or as CTRL-002 `VALIDATED`.
- Later milestones must not treat showcase-scoped empty document lists as a new document engine.
