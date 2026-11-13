# ThreatSight enterprise pilot packaging

**Scope:** controlled design-partner deployment packaging (Phase 3F).

**Not claimed:** commercial production readiness, high availability, disaster recovery, compliance, certification, or SLA.

## Profiles

| Profile | Path | Summary |
| --- | --- | --- |
| Reference Compose | repository root `docker-compose.yml` (+ overlays) | Home/demo reference; synthetic data; tunnel external |
| Hardened pilot Compose | [`compose/hardened/`](compose/hardened/) | Customer VM; OIDC; file secrets; unpublished Postgres |
| Kubernetes/Helm pilot | [`helm/threatsight/`](helm/threatsight/) | External Postgres; customer ingress; secret refs |

See [ADR 0040](../docs/reference/decisions/0040-enterprise-pilot-packaging.md) and [profiles.md](profiles.md).

## Quick links

- [Configuration contract](config/CONTRACT.md)
- [OIDC guide](runbooks/oidc.md)
- [Install](runbooks/install.md) · [Upgrade](runbooks/upgrade.md) · [Rollback](runbooks/rollback.md) · [Backup/restore](runbooks/backup-restore.md)
- [Network/port matrix](runbooks/network.md)
- [Customer runner](runbooks/runner.md)
- [Observability](observability/metrics.md)
- [Release bundle](release/README.md)

## Safety

- Do not commit secrets, tokens, private keys, or live dumps.
- Do not push charts or images to a public registry from this packaging.
- Do not mount production Radar/VulnCheck/signing secrets into disposable clusters.
