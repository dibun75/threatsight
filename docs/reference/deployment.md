# Deployment

Enterprise pilot packaging (Compose hardened + Helm) lives under [`deploy/`](../deploy/README.md). See [ADR 0040](./decisions/0040-enterprise-pilot-packaging.md). That packaging does **not** claim commercial production readiness, HA, SLA, or certification. The home-host stack remains a **reference** installation.

## M0: Docker-first local runtime

This product shares a Docker host with other projects. Follow [DOCKER-HOST-RULES.md](./DOCKER-HOST-RULES.md).

```bash
cp .env.example .env
make up
```

`make up` will:

1. Inspect host port usage.
2. Keep an already-published ThreatSight port, otherwise use the preferred port if free, otherwise the next free port.
3. Write the actual host ports to `.runtime-ports` (gitignored).
4. Start only the `threatsight` Compose project.
5. Verify health endpoints and `docker compose ps`.

Preferred host ports (container ports stay fixed):

| Service | Preferred host port | Container port |
| --- | --- | --- |
| `web` | `3000` | `3000` |
| `api` | `8000` | `8000` |
| `postgres` | `5432` | `5432` |

Actual ports on this host are **not** committed. After startup:

```bash
make ports
```

If preferred `8000` is already bound (for example by Portainer), the API uses the next free host port and records it in `.runtime-ports`.

The web server proxies `/api/*` to `API_INTERNAL_URL` (default `http://api:8000`) and adds the API token on the private network. The token and configured subject/role are never sent to browser code.

## Commands

| Command | Effect |
| --- | --- |
| `make up` | Allocate free ports and start the lab stack (includes demo sidecars) |
| `make up-enterprise` | Production-like overlay: no demo sidecars, Postgres unpublished |
| `make rebuild` | Same as `up`, rebuilding ThreatSight images |
| `make up-tunnel` / `make rebuild-tunnel` | Start with the optional web-only `infra_gateway` attachment |
| `make down` | Stop ThreatSight containers; keep the postgres volume |
| `make backup` | Custom-format `pg_dump`, checksum, and manifest into `backups/` |
| `make inspect` | Read-only listing of host + exact current ThreatSight resources |
| `make clean` | Remove exact allow-listed current containers, images, and network only |
| `make clean-data` | Same, and delete `threatsight_postgres_data` |

Never run `docker system prune -a --volumes`. On a shared Docker host, never stop containers that belong to other projects.

Phase 2 adds `threatsight-worker` to the default stack. It has no host-published port. To run the optional outbound-only customer runner after registering it and injecting its one-time-disclosed credential:

```bash
sudo docker compose --profile customer-runner up -d runner
```

The exact container is `threatsight-runner`; it also publishes no inbound host port. In a real customer deployment it runs inside the customer boundary and points `THREATSIGHT_CONTROL_PLANE_URL` at the approved HTTPS control-plane origin. The Compose profile is a reference topology, not an instruction to place customer credentials in a repository file.

`THREATSIGHT_MICROSOFT_LIVE` defaults to false. Leave it false until an authorized Azure subscription and Entra tenant exist. The runner resolves connector credentials only from `THREATSIGHT_MICROSOFT_CREDENTIALS`, injected at runtime and never committed. Microsoft inventory authentication is separate from ThreatSight user login.

`THREATSIGHT_MERAKI_LIVE` defaults to false. Leave it false until an authorized Meraki organization exists. The runner resolves the Dashboard API key only from `THREATSIGHT_MERAKI_CREDENTIALS`, injected at runtime and never committed. The key is not stored in ThreatSight.

`THREATSIGHT_JUNOS_LIVE` defaults to false. Leave it false until an authorized Junos device, pinned host key, and read-only account exist. The runner resolves the SSH username and private key only from `THREATSIGHT_JUNOS_CREDENTIALS`, injected at runtime and never committed. The current image does not contain a NETCONF client, so enabling the flag does not dial a device. See [Junos connector](./connectors-junos.md).

## Intended later shape

```text
Browser → ThreatSight Web → ThreatSight API
  ├── Governance engine
  ├── Control engine
  ├── Assurance engine
  ├── Evidence store
  └── Intelligence engine
        ↓
      Postgres
```

Exact later services remain implementation decisions. They are not cloned from 1.x.

## In-house deployment (M8)

No mandatory cloud dependency. See [runbook.md](./runbook.md), [api.md](./api.md), and [integrations.md](./integrations.md).

- Lab: `make up` (demo-agent + demo-site on the Compose network, unpublished)
- Enterprise overlay: `make up-enterprise` (in-process adapters, Postgres not published, OpenAPI off by default)
- Production requires `THREATSIGHT_AUTH_MODE=local` or `oidc`, a non-development database credential, an explicit CORS allow-list, and sandbox-by-default. `local` uses an interactive owner bootstrap and does not read a password from the environment. `oidc` still requires the Entra-compatible settings. Auditor is read-only.
- Local evidence in Postgres; `make backup` / restore with `--yes`
- Audit trail at `GET /api/v1/audit` and `/audit`
- Put a reverse proxy in front if you need TLS or SSO; this tree does not ship OIDC

## Production packaging foundation

The enterprise overlay now separates production images from the demonstration images:

- `apps/api/Dockerfile.production` builds an application wheel and runtime dependency wheelhouse, excludes tests and development dependencies, and runs as UID/GID 10001.
- `apps/web/Dockerfile.production` builds a standalone Next.js runtime and runs as UID/GID 1001.
- The lab API and sidecars remove pip/setuptools/wheel after installation; both web runtimes remove npm/corepack tooling.
- The local PostgreSQL derivative replaces the upstream vulnerable `gosu` binary with Alpine `su-exec` while retaining one-shot privilege dropping.
- `migrate` is a one-shot service that runs Alembic before the API starts.
- The production API has `THREATSIGHT_RUN_MIGRATIONS=false` and waits for the migration service to finish successfully.
- Demo agent and demo site remain in the lab profile and are not started by the enterprise overlay.

Validate and build:

- Production startup fails closed for non-OIDC mode, incomplete issuer/audience/client/endpoints/JWKS/redirect configuration, the development database password, wildcard/empty CORS, or disabled sandbox default.
- Browser-provided actor and role headers and legacy shared bearer tokens are ignored; identity and canonical roles derive from validated OIDC claims and persisted memberships.
- Every workspace is tenant-owned. The Radar surface compares session tenant ownership and resolves identity-linked workspace membership on every request.
```bash
sudo docker compose -f docker-compose.yml -f docker-compose.enterprise.yml config --quiet
sudo docker compose -f docker-compose.yml -f docker-compose.enterprise.yml build api web migrate
```

Run only the migration job:

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.enterprise.yml run --rm migrate
```

The production packaging foundation is not yet a complete supported enterprise installation. SAML, external secret stores, high availability, external object storage, signed images, SBOM publication, and cloud or Helm packages remain separate roadmap work. OIDC is implemented, but a real Entra registration and design-partner acceptance remain deployment inputs.


## Demo and reset

Labelled demo: web `/showcase` or `POST /api/v1/showcase/demo/bootstrap`. Idempotent. AUTH-01 still needs `confirm_execution`.

Reset options (current ThreatSight project only):

```bash
make backup
make down                 # keep the volume
make clean-data           # delete threatsight_postgres_data only
make up
```

Never run `docker system prune -a --volumes`. See [troubleshooting.md](./troubleshooting.md).

## Operator checks

- `make ports` — actual host bindings
- `GET /health` on the allocated API port — API live
- `GET /api/v1/ops/status` — deployment status and checklist counts
- Web origin loads the app shell
- `make ps` / `docker compose -p threatsight ps`

