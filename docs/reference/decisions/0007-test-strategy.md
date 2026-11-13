# ADR 0007 — Test strategy

**Status:** Accepted  
**Date:** 2026-08-27

## Context

A foundation without tests is just a folder layout. Testing unimplemented product surfaces would freeze speculative APIs.

## Decision

M0 tests cover domain invariants and foundation HTTP. Compose smoke checks liveness of API and web. UI end-to-end waits until those surfaces exist.

## Consequences

- pytest is the API test runner from day one.
- Host-port allocation and cleanup guards are tested in `tests/test_threatsight_docker.py`.
- Absence of dashboard e2e is intentional, not a gap in M0 exit criteria.
