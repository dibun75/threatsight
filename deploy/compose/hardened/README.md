# Hardened pilot Compose

Customer-controlled single-node packaging. **Not** a commercial production, HA, DR, compliance, or SLA claim.

## Requirements

- External TLS reverse proxy terminating HTTPS to `127.0.0.1:13000` (web).
- Generic OIDC identity provider.
- Secret files under `./secrets/`. Compose file-secrets are bind-mounted; the API runs as uid `10001`, so files must be readable by that user (typically `0644`/`0444` on the host path, or a shared group). Prefer Docker/Kubernetes secret mounts under `/run/secrets` in real pilots.
- Distinct Compose project name (`threatsight-pilot`) so the live reference stack is undisturbed.
- Synthetic loaders disabled by default.

## Secrets layout

```text
secrets/
  postgres_user
  postgres_password
  database_url
  oidc_client_secret
  cloudflare_radar_token      # intel-worker only
  vulncheck_token             # intel-worker only
  evidence_signing_key        # evidence-signer only
```

Never place production tokens from the live reference host into disposable validation environments.

## Validate configuration

```bash
python deploy/scripts/config_check.py --env-file deploy/compose/hardened/.env --profile pilot-compose
```

## Start

```bash
cp .env.example .env
# create secrets/* then:
docker compose -p threatsight-pilot -f docker-compose.yml up -d
```

PostgreSQL is not published on the host. Admin API/web bind to localhost only.
