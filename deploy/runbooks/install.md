# Install runbook (pilot)

**Claims:** pilot packaging only. Not commercial production, HA, SLA, or certification.

## Choose profile

1. Hardened Compose — `deploy/compose/hardened/`
2. Kubernetes/Helm — `deploy/helm/threatsight/`

## Common prerequisites

- External TLS termination (Compose) or customer Ingress (Helm)
- Generic OIDC provider
- External PostgreSQL for Kubernetes profile
- Secret files / Kubernetes Secrets created out-of-band
- `python deploy/scripts/config_check.py` passes without printing secrets

## Compose

1. Copy `.env.example` → `.env`
2. Populate `secrets/`
3. `docker compose -p threatsight-pilot -f docker-compose.yml up -d`
4. Verify localhost health endpoints behind your proxy

## Helm

1. Create namespace and required Secrets
2. `helm lint deploy/helm/threatsight`
3. `helm template` and review — confirm no secret material
4. `helm upgrade --install threatsight deploy/helm/threatsight -n <ns> -f values.customer.yaml`
5. Wait for migrate Job success, then API/web readiness

Do not publish charts or images to a public registry from this repository.
