# Test Strategy

## Purpose

Prove M0–M15: existing product behavior plus showcase-scoped lists, truthful post-retest posture, AUTH-02 naming, and Compose labels/healthchecks. Do not test unimplemented milestones.

## Layers

| Layer | Now | Later |
| --- | --- | --- |
| Domain unit tests | Verdict invariant, assurance status, extraction schema, ingest, CTRL-002 policy, envelope hash, safety, discovery SSRF/robots/heuristics, freshness, executive summary, intelligence schema, connectivity ingest | Extra families |
| API tests | Health/meta; governance CRUD; document ingest; live AUTH-01 FAIL → remediate → PASS; dashboard; discovery; showcase; intelligence explain; event ingest | Additional adapters |
| Compose smoke | `make smoke` against allocated host ports, including M15 meta/intelligence/connectivity needles | Browser e2e |
| UI e2e | Route smoke for dashboard, showcase, discovery, frameworks, intelligence, ops, audit, exports | Full browser workflows |

## Commands

```bash
source venv/bin/activate
THREATSIGHT_RUN_MIGRATIONS=false pytest apps/api/tests -q
pytest tests/test_threatsight_docker.py -q

make test
```

`make test` stages the workspace API sources inside the API container and runs pytest with `THREATSIGHT_TEST_USE_LIVE_DB=true`. That flag means PostgreSQL is reachable. The suite creates a database named `threatsight_test_` plus eight hex characters, migrates only that database, and drops it when the session ends. The preserved runtime database named `threatsight` is refused. Read-only revision and count checks against the preserved database stay outside pytest.

```bash
make up
make smoke
```

## Rules

- Tests must not perform attacks, load exploits, or talk to unauthorized targets.
- CTRL-002 tests use the synthetic demo agent or its in-process twin only.
- Discovery tests use the synthetic demo site or its in-process HTML twin only.
- Tests must not require 1.x fixtures or UI snapshots.
- A failing deterministic invariant is a product defect, not a flaky UI issue.
