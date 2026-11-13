# Troubleshooting

## Ports

Preferred API port `8000` is often taken (for example by Portainer). `make up` chooses the next free host port and writes `.runtime-ports`. Run `make ports`.

The web UI still talks to the API over the Compose network (`http://api:8000`). Host `8080` is only the published mapping.

## Stack will not start

```bash
make ps
make logs
```

Confirm only the `threatsight` project is being started. Do not stop Portainer or other projects. Never run `docker system prune -a --volumes`.

## Empty dashboard

Load the labelled demo from `/showcase`. Counts come from Postgres. Zeros mean there is no data yet. Overview defaults to labelled showcase rows when they exist. Catalogued threats are not tested. Synthetic demo inventory is labelled.

## AUTH-01 refused

- Confirm execution (two-step ConfirmButton).
- `THREATSIGHT_SANDBOX_DEFAULT` must be true.
- `THREATSIGHT_KILL_SWITCH` must be false.
- Lab profile must include demo-agent. Enterprise overlay uses the in-process adapter instead.

## Auditor cannot save

The auditor role is GET-only. Use `operator` for mutations.

## Shared token 401

If `THREATSIGHT_API_TOKEN` is set, send `Authorization: Bearer <token>` or `X-Api-Token`. `/health` and `/ready` stay public.

## Restore failed

Restore replaces the database. Take `make backup` first. Re-run restore with `--yes`.

## Reset the demo

**Reset labelled showcase** on `/showcase` (or `POST /api/v1/showcase/demo/reset`) deletes only `record_origin=showcase` systems and their labelled evidence, then reseeds Nordic Retail. Manual/user systems are left untouched.

Bootstrap is idempotent and will not invent metrics.

To discard the entire local database (current ThreatSight volume only):

```bash
make backup
make down
make clean-data
make up
```

`make clean-data` deletes `threatsight_postgres_data` only. It does not touch other Docker projects.

To restore a previous dump:

```bash
make restore BACKUP=/absolute/path/to/threatsight-YYYYMMDDThhmmssZ.dump
```

## Legal language

If any screen looks like a compliance certificate, it is a defect. The product must keep `legal_compliance_claim` false.
