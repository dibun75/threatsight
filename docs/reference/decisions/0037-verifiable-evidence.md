# ADR 0037: Cryptographically verifiable evidence

Status: Accepted for Phase 3C reference implementation

## Context

Phase 3B produces unsigned evidence manifests (integrity digests). Operators need a way to verify that a downloaded manifest was finalized by a known ThreatSight deployment, without claiming factual correctness or compliance.

## Decision

### Signature envelope `threatsight.signature.v1`

Deterministic canonical JSON fields (sorted keys, compact separators) bound before Ed25519 signing:

- `schema_version` = `threatsight.signature.v1`
- `manifest_schema_version`
- `manifest_id`
- `manifest_digest` (SHA-256)
- `tenant_id`, `workspace_id`, `action_id`
- `closure_outcome` / reviewer subject when present
- `signing_key_id`
- `algorithm` = `Ed25519`
- `deployment_id`
- `signed_at` (UTC Z)
- `previous_signature_id` when applicable

Clients never supply digest, envelope, signature bytes, or keys.

### What a signature proves

- This ThreatSight deployment signed the named manifest digest with the identified key.
- The signed envelope bytes have not changed.
- Signing time and key identity as recorded.

### What it does not prove

Evidence factual correctness; control effectiveness; remediation success; organizational security; auditor approval; legal non-repudiation; regulatory compliance; certification; hardware-backed key protection (unless separately verified).

### Architecture

API creates a bounded signing request after eligibility checks. `threatsight-evidence-signer` claims the request, reloads trusted storage, recomputes the digest, signs only the canonical envelope, and stores public metadata. Private key is file-mounted read-only to the signer alone (uid 10001). No public API signing fallback.

### Trust assumptions

- Host filesystem and Docker secret mounts are intact.
- Database content is trusted for eligibility and envelope fields.
- Clock is approximately correct for `signed_at` display (not a freshness proof).
- Compromised private key allows forged future signatures with that key id until revocation; historical public metadata remains for verification reporting.
- After key rotation, retired keys verify history; only the active key signs new envelopes.
- Offline verification needs only the bundle (manifest, envelope, signature, public key metadata) — not the private key or network.

## Consequences

- Portable bundles support independent verification.
- Phase 3B unsigned digests remain valid labels until signed.
- Later KMS/HSM providers can implement the same `KeyProvider` interface without changing envelope semantics.
