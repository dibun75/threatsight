# Deployment choices and network matrix

## Choices

| Profile | When | Notes |
|---------|------|-------|
| Reference Compose | Founder demo / single host | Not a pilot claim |
| Hardened pilot Compose | Single customer VM | External TLS proxy; OIDC; file secrets |
| Helm pilot | Customer Kubernetes | External Postgres required; ingress off by default |

See `deploy/` and ADR 0040.

## Network / port matrix (pilot)

| Flow | Direction | Port | Notes |
|------|-----------|------|-------|
| Browser → ingress | Inbound | 443 | Customer TLS |
| Ingress → web | Internal | 3000 | ClusterIP / localhost bind |
| Web → API | Internal | 8000 | |
| API/workers → Postgres | Egress | 5432 / TLS | Customer DB |
| API → OIDC IdP | Egress | 443 | Discovery/token/JWKS |
| Intel worker → public sources | Egress | 443 | |
| Customer runner → API | Egress only | 443 | No inbound to runner |
| Postgres host publish | — | **none** by default | |

Reference host currently binds API/web/Postgres to localhost only; Cloudflare Tunnel provides public HTTPS. Do not restart the tunnel connector casually.
