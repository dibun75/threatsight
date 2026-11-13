# ADR 0040: Enterprise pilot deployment packaging

Status: Accepted for Phase 3F reference implementation

## Context

Phases 3A–3E delivered intelligence, readiness, signing, and response coordination on a single-host Docker Compose reference. Design partners need repeatable install, upgrade, backup, rollback, and removal for:

1. hardened single-node Compose;
2. customer-managed Kubernetes (Helm);
3. customer cloud/on-prem with external PostgreSQL, OIDC, and customer-managed secrets.

The live single-host deployment must remain a **reference** installation—not production-grade, HA, DR-capable, compliant, certified, or SLA-backed.

## Decision

### Deployment profiles

| Profile | Identity | Data | Postgres | Ingress | HA claim |
| --- | --- | --- | --- | --- | --- |
| `reference` | local/OIDC/public_demo as configured | synthetic allowed | bundled | Cloudflare Tunnel external to stack | none |
| `pilot-compose` | OIDC default; local break-glass only | synthetic opt-in | unpublished or external | customer TLS proxy | none |
| `pilot-kubernetes` | OIDC required | synthetic opt-in | **external required** | customer Ingress/TLS | none |

### Trust boundaries

```text
[Browsers] --TLS--> [Customer ingress] --> [web] --> [api]
                                              |
                         +--------------------+--------------------+
                         |                    |                    |
                   [intel-worker]      [evidence-signer]    [customer-runner]
                         |                    |                    |
                    Radar/VulnCheck      signing private      customer nets
                    tokens (file)        key (file)          (outbound only)
                         |                    |
                         +---------+----------+
                                   |
                            [PostgreSQL]
                         (customer-managed
                          for k8s/pilot)
```

### Runtime inventory

| Component | Replicas | Persistent state | Secrets | Notes |
| --- | --- | --- | --- | --- |
| web | horizontal | none | none | proxies `/api` |
| API | horizontal* | sessions in DB | OIDC client secret; DB URL | *session cookies are server-validated |
| intelligence worker | multi via DB locks | none | Radar + VulnCheck tokens | worker-only mounts |
| evidence signer | multi via leases | none | Ed25519 private key | signer-only mount |
| PostgreSQL | external / single | all product data | DB credentials | HA is customer DB duty |
| customer runner | per deployment | none | runner credential | outbound-only |
| migration Job | exactly one | schema | migration DB role | controlled, not concurrent |
| backup tooling | scheduled/manual | dump files | encryption key | never contains app secrets |

### Ordering

**Startup:** Postgres ready → migration Job (once) → API/web → workers/signer → runner (optional).

**Upgrade:** preflight → backup → image pull → migration Job → roll API/web → workers/signer → verify. Never auto-downgrade schema.

**Rollback:** application image rollback only while schema remains compatible; otherwise restore-required from verified dump.

### Secret ownership

| Secret | Owner component | Never on |
| --- | --- | --- |
| OIDC client secret | API | workers, signer, web, runner |
| Radar / VulnCheck tokens | intel-worker | API, web, signer, runner |
| Evidence signing private key | evidence-signer | all others |
| Runner credential | customer-runner | control plane pods |
| DB passwords | API/migrate/backup roles | charts values / Git |

### Explicit non-claims

Pilot 3F does **not** mean commercial production readiness, HA validation in a customer cluster, SLA, support commitment, compliance certification, or paid-pilot acceptance.

## Consequences

- Packaging lives under `deploy/` with profile-specific Compose and Helm.
- Production/pilot profiles fail closed on insecure defaults.
- Generic OIDC is the enterprise default; local auth is break-glass only.
- Live reference Compose is not migrated to Kubernetes by this ADR.
