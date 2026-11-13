# ADR 0028 — Deterministic conservative Radar clustering

## Status

Accepted for Phase 1.

## Context

Multiple authorities may report the same vulnerability or related development. Removing or invisibly merging records would destroy provenance, while opaque semantic or LLM grouping would be difficult to reproduce and could create false relationships.

## Decision

- Keep every source event unchanged and independently addressable.
- Create exact-duplicate clusters only when normalized titles and CVE sets match.
- Create related-event clusters only for a shared CVE across at least two source records.
- Persist stable cluster keys, membership relationship type, contributing factors, algorithm version, and timestamps.
- Rebuilding clusters is deterministic and idempotent.
- Do not cluster solely on vendor, product, geography, generic title words, vector similarity, or LLM output.
- Expose grouping reasons and limitations to the API and UI.

## Consequences

The algorithm intentionally misses some semantic relationships rather than creating weak false positives. A future version may add reviewed deterministic factors, but changing the algorithm requires a new version and regression fixtures.
