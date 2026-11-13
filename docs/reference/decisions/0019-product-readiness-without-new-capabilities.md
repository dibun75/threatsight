# ADR 0019 — Product readiness without new capabilities

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M10 asks for a professional showcase: demo flow, documentation, UX consistency, Docker/ops verification, security review, and labelled synthetic data. Adding new control families, scanners, or GRC features would violate the milestone.

## Decision

- Polish the existing `/showcase` walkthrough into the primary assurance loop. Do not add engines or APIs.
- Seed only labelled records on existing models (second inventory system, manual CTRL-002 attestation). No new control families.
- Document start, demo, reset, architecture, deployment, troubleshooting, and a CV summary.
- Verify Compose labels, health checks, backups, and shared-host cleanup limits.
- Record the security review against existing controls. Do not add SSO or a legal-compliance engine.

## Consequences

- A new reviewer can start the stack and walk the product in minutes.
- Demo data remains synthetic and labelled.
- M10 is a readiness milestone, not a capability milestone.
