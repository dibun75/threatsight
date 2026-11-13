# Upgrade runbook (pilot)

1. **Preflight** — `deploy/scripts/upgrade_preflight.sh <api-image> <web-image>`
2. **Backup** — `deploy/scripts/backup.sh ./backups` (encrypt before off-host transfer)
3. **Migration preview** — review Alembic revisions; test upgrade/downgrade on a restored clone
4. **Pull images** — ensure digests available on the host/cluster
5. **Migrate** — run controlled migration Job / Compose migrate service **once**
6. **Roll** — API and web first; then intel-worker; then evidence-signer
7. **Verify** — health, auth login, source freshness, signer health, schema version
8. **Decision** — continue or enter rollback runbook

Never automatically downgrade schema. Application image rollback is only valid while schema remains compatible.

## Single-host live stack

The public site runs on `docker-compose.yml` plus six overlays (tunnel, signing, threatfox, abusech,
vulncheck, telemetry). Never run plain `make up` there: it loads only the base file and recreates
`web` off the tunnel network, which takes threatsight.io down.

One-time setup: `cp deploy/live.env.example .deploy.env` and fill in the host paths and any live
variables not already in `.env`. Then, from a clean checkout of the commit to ship:

```
make deploy
```

It checks every overlay's secret file exists, validates the compose config, takes
`backups/threatsight-predeploy-<UTC>.dump`, builds every image tagged with the commit SHA (the
evidence signer is never rebuilt; it keeps `THREATSIGHT_SIGNER_IMAGE_TAG`), starts the stack, runs
`alembic upgrade head`, and waits for all services to report healthy.

Rollback: set `THREATSIGHT_IMAGE_TAG=<previous sha>` in `.deploy.env` and run
`make deploy ARGS=--skip-build`. Images from earlier deploys stay on disk under their SHA tags until
pruned. Restore the predeploy dump only if a migration must be undone.
