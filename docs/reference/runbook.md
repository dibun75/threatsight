# Operational runbook

Lab default: `make up`. Enterprise overlay: `make up-enterprise`.

## Daily checks

1. `make ports` — confirm host bindings.
2. `GET /health` and `GET /ready` on the API port.
3. `GET /api/v1/ops/status` — database_ok, auth_mode, checklist_pass.
4. Web `/ops` for the same view.
5. Web `/showcase` for the labelled walkthrough. AUTH-01 still requires confirmation.

## Demo reset

Bootstrap is idempotent. To wipe local data: `make backup` then `make clean-data` then `make up`. That deletes only `threatsight_postgres_data`. See [troubleshooting.md](./troubleshooting.md).

## Start / stop

```bash
cp .env.example .env   # rotate the Postgres password first
make up                # lab: api, web, postgres, demo-agent, demo-site
make smoke
make down              # keeps the volume
```

Enterprise-like (no demo sidecars, Postgres unpublished):

```bash
# Set THREATSIGHT_API_TOKEN in .env first.
make up-enterprise
```

Do not mix lab and enterprise in one thoughtless restart. `make down` then the intended `up` command.

## Backup / restore

```bash
make backup                          # writes verified backups/threatsight-*.dump
make restore BACKUP=/absolute/path/to/threatsight-YYYYMMDDThhmmssZ.dump
```

Restore replaces the database. Take a fresh backup first.

## Kill switch

Set `THREATSIGHT_KILL_SWITCH=true` and `make restart` to refuse CTRL-002 execution and discovery fetch.

## Logs

```bash
make logs
```

Structured JSON when `THREATSIGHT_LOG_JSON=true`. Correlate with `X-Request-ID`.

## Do not

- Publish Postgres on an untrusted network.
- Commit `.env` or `.runtime-ports`.
- Point assurance adapters at non-authorized real systems.
- Treat export bundles as legal compliance evidence.
