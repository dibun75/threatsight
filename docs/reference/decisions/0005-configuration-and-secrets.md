# ADR 0005 — Configuration and secrets

**Status:** Accepted  
**Date:** 2026-08-27

## Context

The product is intended for in-house deployment. Credentials cannot live in git or images.

## Decision

Environment variables only, documented in `.env.example`. Compose injects runtime env. Images do not copy `.env`.

## Consequences

- Local onboarding is `cp .env.example .env`.
- Production must provide a secret source; none is chosen yet (no cloud KMS requirement).
