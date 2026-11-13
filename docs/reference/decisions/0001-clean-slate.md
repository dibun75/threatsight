# ADR 0001 — Clean-slate product

**Status:** Accepted  
**Date:** 2026-08-27

## Context

ThreatSight 1.x exists in a separate repository with a scanner-centric architecture and UI. ThreatSight 2 is an AI assurance platform.

## Decision

Start from an empty architecture. Do not copy 1.x code, UI, scanner design, billing, intelligence feeds, or documentation trees. Re-implement a capability only if it is independently approved in the 2.0 feature register.

## Consequences

- Faster architectural honesty; no hidden 1.x coupling.
- Some useful operational lessons from 1.x must be rediscovered or written as new ADRs.
- Contributors must not "save time" by pasting 1.x screens or scanners.
