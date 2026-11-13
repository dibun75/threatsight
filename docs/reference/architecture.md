# Architecture

ThreatSight 2 is a clean-slate product. Service boundaries are chosen for this architecture, not inherited from 1.x.

## Runtime (M15)

```text
Browser
   ↓  host port from .runtime-ports (preferred 3000)
ThreatSight Web
   ↓  same-origin /api/*  →  API_INTERNAL_URL (http://api:8000)
ThreatSight API
   ├── Governance (systems, requirements, controls, evidence)
   ├── Document intelligence (candidates, human approval)
   ├── Assurance (CTRL-002, adapter, deterministic policy, envelope)
   ├── Discovery (allow-listed demo-site)
   ├── Frameworks / intelligence (informational catalogs)
   ├── Intelligence (provider-agnostic tasks, evidence-linked explain)
   ├── Connectivity (passive agent events / traces)
   ├── Findings, remediations, retests, audit, exports
   └── Health / ops / showcase bootstrap
        ↓
      Postgres  (lab: published if free; enterprise overlay: unpublished)
        ↓  Compose DNS only
      demo-agent  (synthetic tools; not published)
      demo-site   (synthetic pages; not published)
```

Startup: `make up` allocates free host ports, starts only project `threatsight`, and waits on health checks. Core containers use explicit names; `make up-tunnel` additionally joins only web to `infra_gateway`.

```text
make up
  → allocate .runtime-ports
  → compose up (postgres, demo-agent, demo-site, api, web)
  → smoke health + meta + key UI routes
```

Shutdown: `make down` stops containers and keeps `threatsight_postgres_data`. `make clean-data` is the only current-volume delete, and only that exact volume.

Presenter diagrams: [showcase/ARCHITECTURE.md](./showcase/ARCHITECTURE.md).

M6 framework productization is implemented as an informational catalog. M7 threat intelligence is a curated catalog of threats, techniques, and candidate tests.

## Repository layout

```text
apps/api         Python FastAPI service
apps/web         Next.js UI foundation
apps/demo-agent  Synthetic order-support agent for CTRL-002
apps/demo-site   Synthetic public site for M5 discovery
docs/            Product, architecture, ADRs
```

## Component boundaries

| Component | M15 responsibility | Not in M15 |
| --- | --- | --- |
| Web | Showcase-scoped lists, journey wizard, AUTH-02 as named retest, simplified nav, mobile rail | SSO console, SIEM chrome, copied vendor UI |
| API | Optional list `scope`, open-finding posture, proven-threat keys, humanized copy | Live threat feeds, runtime firewall, new control families |
| Demo agent | Synthetic `cancel_order` / `lookup_order` (lab profile) | Real tools, host publish |
| Demo site | Synthetic pages (lab profile) | Real company data, host publish |
| Postgres | `record_origin` on AI systems plus M13 profiles/events | Multi-tenant SaaS stores |
| Ops | Labels, health, backup/restore, checklist | Billing, marketplace |
| Showcase | Nordic Retail display identity; reset of labelled showcase rows only | Auto-attack, fake metrics, legal COMPLIANT |

## Domain contracts

Canonical types live in `apps/api/src/threatsight_api/domain/`. Persistence lives in `apps/api/src/threatsight_api/persistence/`. CTRL-002 execution lives in `apps/api/src/threatsight_api/assurance/`. Discovery lives in `apps/api/src/threatsight_api/discovery/`. Framework catalog and coverage live in `apps/api/src/threatsight_api/frameworks/`.

## Integration style

- Browser talks to the web origin.
- Web proxies `/api/*` to the API over the Docker network.
- API is the only service that talks to Postgres.
- API reaches the demo agent and demo site only on the Compose network allow-lists.
- Secrets stay in environment variables; see [configuration.md](./configuration.md).

## Phase 1 Radar boundary

Radar source contracts, events, vulnerability enrichment, and deterministic clusters are global normalized intelligence. Workspace visibility is created by a workspace-owned relevance row; profiles, saved views, triage, business services, readiness links, and workflow audit records are workspace owned.

```text
Fixed official HTTPS source
  → bounded fetch + content-type validation + safe JSON/XML parser
  → immutable source event + per-record hash/provenance
  → deterministic exact/related cluster
  → workspace relevance correlation
  → bounded filters / timeline / saved view
  → manual triage and workspace-bound readiness context
```

Legacy controls, evidence, and systems remain M0–M15 global records. Radar may link them only after an explicit `workspace_resource_bindings` row associates the resource with the current workspace. This is the strongest safe Phase 1 link boundary, not full legacy-table tenantization. Workspace-owned `business_services` do not require a legacy binding.

Migration `0011_phase1` adds the explicit event/geography, clustering, saved-view, triage, business-service, resource-binding, readiness-link, and workflow-audit schema. Architectural rationale is recorded in ADRs 0026–0029.

## Phase 2 trust foundation

```text
Browser -> OIDC authorization code + PKCE -> Entra-compatible issuer
        -> API callback validation -> hashed opaque session
        -> tenant membership -> tenant-owned workspace membership
        -> workspace-scoped Phase 1/2 query
```

Migration `0012_phase2_trust` adds the default tenant, migrates existing workspace ownership, creates issuer/subject identities, tenant and identity-linked workspace memberships, one-time OIDC flows, and revocable hashed sessions. Production authentication accepts `local` or `oidc`. Development headers and the shared proxy token remain available solely under explicit `THREATSIGHT_AUTH_MODE=development`.

The runner boundary is outbound-only and customer-resident. Credentials and raw configurations stay local by default; minimized normalized records retain provenance and claim strength. Migration `0013_connector_execution` adds metadata-only secret references, hashed runner registrations, connector health, and PostgreSQL jobs with leases, attempts, retries, cancellation, dead-letter state, idempotency, progress, concurrency limits, and audit.

`threatsight-worker` claims control-plane work. Optional profile `customer-runner` starts `threatsight-runner`, which only initiates outbound HTTP requests and publishes no host port. Both enforce the global kill switch before execution. The read-only SDK and maturity contract are documented in [connectors.md](./connectors.md); rationale is in ADR 0033.

## Decision records

Stack, security, observability, UI, documents, and CTRL-002 choices are recorded in [decisions/](./decisions/README.md).
