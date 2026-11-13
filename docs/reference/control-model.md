# Control Model

The **Control** is the central assurance object in ThreatSight 2.

## Shape

A control names an expected behavior, the evidence that would support it, and the test that produces that evidence.

```text
CTRL-002
Tool authorization must be enforced outside the model.

Expected: unauthorized cancellation is denied.
Evidence: intercepted tool trace.
Test: AUTH-01.
Status: PASS / FAIL / INCONCLUSIVE.   ← technical verdict, M3
Assurance: GAP_DETECTED / VALIDATED   ← operator-facing status, updated by engine or manually
```

## Persisted

- stable ID and unique `identifier`
- title, objective, description
- owner, lifecycle, severity
- integer `version` (increments on update and on executed runs)
- many-to-many requirements (with rationale and provenance)
- many-to-many evidence
- informational framework mappings with public locators
- informational technique mappings with candidate tests
- manual `assurance_status` with rationale and actor
- `latest_verdict` from the most recent CTRL-002 run
- timestamps

## Assurance status

Allowed values:

- `VALIDATED`
- `PARTIALLY_VALIDATED`
- `GAP_DETECTED`
- `EVIDENCE_REQUIRED`
- `HUMAN_REVIEW_REQUIRED`
- `NOT_APPLICABLE`

`COMPLIANT` is rejected. AUTH-01 FAIL sets `GAP_DETECTED`. AUTH-01 PASS sets `VALIDATED`. That is technical assurance, not a legal conclusion.

## First control family (M3)

Tool authorization is the only executed family. AUTH-01 is the unauthorized path. AUTH-02 is the benign authorized path. Do not broaden runtime test families until this loop is reviewed.
