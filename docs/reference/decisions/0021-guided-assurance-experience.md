# ADR 0021 — Guided assurance experience without new engines

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M11 must make ThreatSight understandable in two minutes: what it is, why AI assurance matters, what needs attention, and how evidence and tests support decisions. Adding engines, scanners, or legal-compliance claims would violate the milestone.

## Decision

- Keep M1–M10 data models and APIs. Derive the decision dashboard from existing dashboard counts.
- Show first-run onboarding when inventory is empty. Visualize the assurance lifecycle on Dashboard and Showcase.
- Tell the labelled demo story (system → risk → CTRL-002 failure → evidence → remediation → retest) without implying production discovery.
- Group navigation around the assurance loop. Use `LoadingState` consistently.

## Consequences

- Charts are percentages and stacked counts from persisted rows, not decorative scores.
- `legal_compliance_claim` remains false. `COMPLIANT` remains invalid.
- M11 is a product-experience milestone, not a capability milestone.
