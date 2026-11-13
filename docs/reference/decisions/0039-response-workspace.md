# ADR 0039: Response workspace and crisis coordination

Status: Accepted for Phase 3E reference implementation

## Context

Phases 3A–3D.1 produce intelligence, readiness recommendations, accountable actions, and signed evidence. Operators need a controlled place to coordinate an assessment, exercise, or incident response without treating every external observation as an incident and without creating a parallel action system.

## Decision

### Response workspace

A tenant/workspace-scoped coordination record that links existing intelligence, readiness actions, evidence manifests/signatures, graph services, and decisions. It does not copy raw connector payloads or replace readiness_actions.

### Modes (mutually exclusive intent)

| Mode | Meaning |
| --- | --- |
| `assessment` | Structured investigation of relevance and uncertainty |
| `exercise` | Synthetic or planned practice; always labelled |
| `incident_response` | Coordination under a declared or suspected incident posture |

Mode is not declaration. An `incident_response` mode may still have declaration `not_declared` until an authorized administrator declares.

### Evidence assessment

`unreviewed` · `suspected` · `supported` · `conflicting` · `not_supported` · `unknown`

### Incident declaration

`not_declared` · `suspected_incident` · `confirmed_incident` · `ruled_out`

No Radar, media, KEV, EPSS, VulnCheck, or vulnerability match may set declaration automatically.

### Coordination lifecycle

`draft` → `monitoring` | `assessing` → `activated` → `recovery_review` → `closed`  
Also: `cancelled` from draft/monitoring/assessing; reopen closed → assessing with audit.

`activated` means coordination is active—not that compromise is confirmed.

### Authorization

| Transition | Minimum role |
| --- | --- |
| Propose / draft | operator |
| Activate | workspace-admin / platform-admin |
| Confirm incident | workspace-admin / platform-admin + rationale + reviewed evidence |
| Assign roles / timeline / decisions / drafts | operator+ (admin for declaration) |
| Finalize sitrep / request snapshot signature | operator+ |

RBAC remains product-authoritative; response roles are operational assignments only.

### Signing

Finalized response snapshots produce a readiness evidence manifest on a linked readiness action and use the existing Phase 3C signer. Signature proves snapshot integrity only.

### Jurisdiction profiles

Informational, sourced, configurable. Legal applicability and reporting obligation default to `not_determined`. Explicit “not legal advice.” No automatic regulator notification.

## Consequences

- One coordination surface reuses Phase 3A–3C artifacts.
- Exercises cannot be confused with confirmed incidents in list/detail/command-center.
- Append-only timeline with supersession links preserves history.
