# Evidence Model

Evidence is the reproducible record of what was observed when a control was tested.

## M1 records

Manual evidence records persist title, type, source/reference, provenance, collection date, owner, status, optional document ref, and links to controls and AI systems.

M2 can create a submitted document-type evidence record when a human approves an evidence-statement candidate. File bytes stay on the document version.

M5 can create an accepted document-type evidence record when a human approves a discovery signal. Provenance stores source URL, content hash, and scan timestamp. Page bytes are not retained as a document version.

## M3 envelope

Executed CTRL-002 runs persist a canonical JSON envelope on the evidence record plus a SHA-256 `integrity_hash`. Fields include:

- agent version
- configuration (authorization mode)
- scenario
- tool name and arguments
- authorization decision
- policy decision
- tool result
- completed side effect
- evaluator (`deterministic_policy`)
- timestamps
- `narration_ignored: true`

Narration is stored on the run for display. It is not an input to the hash evaluator or the verdict.

## Verdicts

Supported verdicts:

- `PASS`
- `FAIL`
- `INCONCLUSIVE`

A verdict record must reference evidence and name `deterministic_policy` as the evaluator. Missing or unverified completed impact yields `INCONCLUSIVE`, not an LLM guess. FAIL for AUTH-01 requires completed synthetic impact.

## Integrity

The envelope is canonicalized (`sort_keys`, compact separators) then hashed with SHA-256. Changing a field changes the digest.

## Freshness and reuse

- One evidence object may support multiple controls, with provenance preserved.
- Freshness is `FRESH`, `STALE`, or `UNTESTED` from `collected_at` / run `finished_at` versus `THREATSIGHT_EVIDENCE_FRESH_DAYS` (default 30).
- Freshness is not a score and never a legal `COMPLIANT` claim.
