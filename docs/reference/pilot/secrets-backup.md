# Secrets and backup responsibilities

## Secret boundaries

| Secret | Owner | Mount / consumer |
|--------|-------|------------------|
| Database URL / password | Customer (pilot) | API, workers, migrate (role-separated where practical) |
| OIDC client secret | Customer IdP | API only |
| Radar token | Operator / customer | Intel worker only |
| VulnCheck token | Operator / customer | Intel worker only |
| Evidence signing private key | Customer | Signer only; never in values |
| Runner credential | Customer | Runner only |

Compose file-secrets must be readable by container uid `10001`. Prefer `/run/secrets` mounts.

## Backup classes

| Class | Guided demo | Controlled pilot |
|-------|-------------|------------------|
| Local `-Fc` dump | Required + verified | Required |
| Encrypted before transfer | Recommended | Required before off-host |
| Off-host destination | Not claimed | **Customer confirms** |
| Restore-to-clone drill | Required | Required |
| RPO/RTO | Customer objectives — **not product guarantees** | Same |

A local encrypted drill is **not** off-host protection.

Do not upload current reference data without explicit authorization.
