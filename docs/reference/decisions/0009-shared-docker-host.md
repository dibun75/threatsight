# ADR 0009 — Shared Docker host isolation

**Status:** Accepted  
**Date:** 2026-08-27

## Context

ThreatSight runs on a shared Docker host. Preferred ports may already belong to Portainer or other stacks. Broad prune/cleanup commands would destroy unrelated work.

## Decision

- Compose project name is `threatsight`; the historical `threatsight-2` deployment was consolidated under ADR 0030.
- `make up` allocates free host ports and records them in `.runtime-ports`.
- Cleanup targets only exact allow-listed resources carrying the current Compose project labels.
- The postgres named volume is preserved unless `make clean-data` is used.
- `docker system prune` is forbidden in this repository's operator docs and scripts.

## Consequences

- README cannot hard-code a single host URL for every machine.
- Operators must read `.runtime-ports` or `make ports` after startup.
- Other projects on the host remain untouched by ThreatSight-2 bring-up and cleanup.
