# Pilot operations

Single host. There is no second instance and no claim of high availability. If the host or its disk fails, the site stays down until the host is rebuilt and a backup is restored.

## What an administrator can see

`GET /api/v1/ops/execution` requires `workspace-admin` or `platform-admin`. It returns job counts, runner counts, connector maturity counts, the oldest queued time, active lease count, unrevoked credential count, and the kill-switch flag. It does not return credentials, secret locators, configuration, or payloads.

`GET /health` stays a liveness probe. `GET /ready` reports dependency readiness without secrets. `GET /api/v1/ops/status` reports version, environment, auth mode, and whether the deployment is still the reference environment.

## Support cases

| Case | Action |
| --- | --- |
| API unavailable | Check the API container and `/health`. Do not restart unrelated stacks. |
| Web unavailable | Check the web container and the same-origin proxy. |
| Database unavailable | Check Postgres. Do not drop the volume. |
| Migration failure | Stop the new API. Restore the validated backup onto a clone before touching the preserved database again. |
| Bad reference load | The synthetic loader is idempotent. Do not relabel fixture rows as live. |
| OIDC outage | Production mode fails closed. Reference mode is only for the synthetic host. |
| Cloudflare outage | The tunnel is shared infrastructure. Do not edit it from this repository. Use the local ports to confirm the origin. |
| Runner outage | Confirm outbound 443, the credential file, and the registration status. |
| Source rate limit | Leave the job to retry until the attempt cap, then dead-letter. Do not raise the cap during an incident. |
| Stale data | Read the collection time. Stale is a label, not a silent success. |
| Backup failure | Keep the previous encrypted artifact. Do not delete it to free space. |
| Disk pressure | Remove old local drill files only after the manifest says they are drill artifacts. |
| Certificate or CA failure | Fix `SSL_CERT_FILE` or the proxy CA. Do not disable verification. |
| Security incident | Preserve audit rows and container logs, revoke runner credentials, turn on the kill switch if collection must stop. |
| Suspected credential exposure | Revoke the credential, rotate it, and treat the old file as burned. |
| Kill switch | `THREATSIGHT_KILL_SWITCH=true` stops new execution. Restart the API after the flag is set. |
| Rollback | Redeploy the previous immutable image tag. Do not start an image that cannot read the current database revision. |
| Offboarding | Revoke runners, export or destroy the final backup as the partner instructs, then delete the workspace rows. |

## Upgrade

Back up and encrypt. Build immutable images. Scan them. Rehearse the migration on a clone. Tell the named approvers. Apply the migration only when the new image contains the whole chain and the clone rolled back. Smoke-test health, a workspace read, and the reference banner if reference auth is still on. Capture the image ids and the database revision. Roll back to the previous image if the smoke test fails and the migration was not applied. If the migration was applied, restore the backup onto a clone before deciding to restore the preserved database.

## Runner symptoms

Cannot connect: DNS, proxy, CA, or HTTPS refusal. Authenticates but cannot claim: wrong workspace, revoked credential, or kill switch. Lease expiry: the runner was too slow or lost the network; the job retries or dead-letters. Job stays queued: no connected runner for that workspace. Repeated retries: read the dead-letter reason before requeueing. Clock skew: fix the customer clock; the control plane allows the OIDC skew already configured and does not widen it for a runner. Version mismatch: upgrade the runner to the pinned tag. Customer shutdown: expected; the control plane shows the runner disconnected. Control-plane outage: the runner retries and does not store raw responses locally.
