# Availability and leader behavior

**Not a high-availability claim.** Configuring replicas does not make ThreatSight HA.

| Component | Replicas | Safety mechanism | Notes |
|-----------|----------|------------------|-------|
| web | horizontal | stateless | OK behind customer ingress |
| API | horizontal | cookie/session in DB | Session assumptions must remain shared-DB |
| intelligence worker | multi-pod only with locks | `pg_try_advisory_lock` / collectors | Over-replication without locks races collectors |
| evidence signer | multi-pod only with leases | `FOR UPDATE SKIP LOCKED` + lease | Prefer 1–2 with lease TTL |
| migration | exactly one Job | Helm Job / Compose one-shot | Never parallelize upgrades |
| customer runner | per workspace/deployment | scoped credentials | Deploy separately |
| PostgreSQL | external | customer DB service | HA delegated to customer |

Failure behavior: pods restart; leases expire; collectors re-acquire locks. Rollback of application images is allowed only when schema remains compatible — never auto-downgrade the database.
