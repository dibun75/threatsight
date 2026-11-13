# Evidence signing runbook

Private keys are never pasted, logged, or committed. Generate and mount them on the host only.

Do not assume host Python has ThreatSight or pydantic installed. The supported generator runs inside the production API image.

## Generate the reference key (elevated)

Inspect the path first. Refuse overwrite. Record only `key_id` and fingerprint from stdout — never private-key bytes.

```bash
sudo mkdir -p /var/lib/threatsight/evidence-signing
test ! -e /var/lib/threatsight/evidence-signing/ed25519-private.pem
sudo docker run --rm --user 0:0 \
  --entrypoint python \
  -v /var/lib/threatsight/evidence-signing:/keys \
  -v "$PWD"/scripts/generate_evidence_signing_key.py:/tmp/generate_evidence_signing_key.py:ro \
  threatsight-api:37877a2 \
  /tmp/generate_evidence_signing_key.py --dir /keys
sudo chown root:root /var/lib/threatsight/evidence-signing
sudo chown 10001:10001 /var/lib/threatsight/evidence-signing/ed25519-private.pem
sudo chmod 0400 /var/lib/threatsight/evidence-signing/ed25519-private.pem
sudo chmod 0444 /var/lib/threatsight/evidence-signing/ed25519-public.pem \
  /var/lib/threatsight/evidence-signing/ed25519.fingerprint \
  /var/lib/threatsight/evidence-signing/ed25519.key-id
```

Replace `threatsight-api:37877a2` with the current verified API image tag when pinning advances. Host `python3 …/generate_evidence_signing_key.py` is unsupported unless that interpreter already has the ThreatSight package and its cryptography/pydantic dependencies.

## Enable the signer

```bash
export THREATSIGHT_EVIDENCE_SIGNING_KEY_PATH=/var/lib/threatsight/evidence-signing/ed25519-private.pem
export THREATSIGHT_EVIDENCE_SIGNING_KEY_ID="$(sudo cat /var/lib/threatsight/evidence-signing/ed25519.key-id)"
export THREATSIGHT_SIGNER_IMAGE_TAG=<merge-sha>
sudo -E docker compose -f docker-compose.yml -f docker-compose.signing.yml up -d --no-deps --no-build evidence-signer
```

The signer bootstraps public-key metadata and activates the key for its deployment. Confirm API, web, intel-worker, postgres, runner, demo, and tunnel do not mount the private key.

## Offline verification

```bash
python3 scripts/threatsight_verify_evidence.py /path/to/evidence-verification-<id>.json
```

## Rollback

Stop the signer, leave manifests and public signature metadata in the database, and keep the private key offline. Downgrade of `0027_verifiable_evidence` removes only Phase 3C tables.
