# ADR 0008 — UI foundation

**Status:** Accepted  
**Date:** 2026-08-27

## Context

The feature register requires a new UI from scratch. M4 is the executive dashboard. M0 still needs an interface so the Docker skeleton is a product, not an API-only repo.

## Decision

Ship a Next.js app shell with original design tokens (paper/ink institutional, not SOC-scanner chrome). Routes for later work exist as explicit placeholders that name the milestone they belong to. No fake metrics, no 1.x layout, no copied components.

## Consequences

- Design work in M4 extends tokens and shell rather than replacing a cloned 1.x theme.
- Placeholder pages make scope honest to reviewers.
