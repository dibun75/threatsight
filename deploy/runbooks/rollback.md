# Rollback runbook (pilot)

## Application-only rollback

When the new schema is backward-compatible with the previous application:

1. Redeploy previous image digests for API/web/workers/signer
2. Do **not** run `alembic downgrade` automatically
3. Verify health and critical journeys

## Restore-required rollback

When schema is incompatible or data corruption is suspected:

1. Stop writers (API/workers/signer)
2. Restore verified dump into a new database or replace after offline window
3. Re-provision secrets (tokens, signing key, OIDC) — they are **not** in the dump
4. Start previous images against restored schema
5. Verify evidence signatures still validate with the restored public metadata + current/continuous signing key

Signing-key continuity: if the private key was rotated and lost, historical signatures remain verifiable only with retained public keys; new signatures need the active private key.
