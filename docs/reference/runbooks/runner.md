# Runner package

The runner image is the pinned API image, user 10001, read-only root, `tmpfs` on `/tmp`, all capabilities dropped, `no-new-privileges`, a 512 MB memory limit, and a localhost health check. The compose file is `deploy/runner/docker-compose.yml`. The credential example is a placeholder. Do not commit a real credential. `deploy/runner/runner-credential` is gitignored.

## Registration

1. A workspace administrator creates a runner registration. The credential is returned once.
2. The customer writes it to a file mounted read-only at `/run/secrets/runner-credential`. It is not a command argument. Outside development, an environment variable is rejected.
3. The runner connects outbound to an HTTPS control plane. Plain HTTP is refused unless `THREATSIGHT_ENV` is `development` or `test`.
4. The control plane records the runner health and version on heartbeat.
5. Rotation issues a new credential and revokes the old hash. The old file stops authenticating.
6. Revocation stops new claims. A leased job fails closed on the next progress call. Audit rows remain.
7. Queued jobs for a revoked runner stay queued or are cancelled by an administrator. They are not dispatched to another tenant.

Localhost health returns `{"status":"ok"}` and does not read the credential file.

## Egress

Allow TCP 443 to the control-plane hostname only, plus the approved vendor endpoints for the connectors in scope. Proxy and CA settings, when needed, are `HTTPS_PROXY` and `SSL_CERT_FILE`. Do not add an undocumented proxy.

## Upgrade, uninstall, and logs

Pull the pinned image tag the control plane documents, replace the container, and confirm `/health` on localhost. Uninstall is `docker compose down` in `deploy/runner` and deletion of the credential file. The registration is revoked on the control plane first. Logs are the container json-file driver. Rotate them on the host. Collect logs only after confirming they contain no credential; the process is written not to print the credential.

## Troubleshooting

See the pilot operations runbook for connection, claim, lease, queue, retry, dead-letter, kill switch, clock skew, proxy, version, and shutdown cases. The steady state does not require the central worker.
