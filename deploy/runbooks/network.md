# Network / port matrix (pilot)

| Flow | Direction | Port | Notes |
| --- | --- | --- | --- |
| Browser → customer TLS proxy | inbound | 443 | Customer-managed |
| Proxy → web | internal/localhost | 3000 / 13000 | Compose binds `127.0.0.1` |
| web → API | internal | 8000 | ClusterIP / Compose network |
| API → PostgreSQL | egress | 5432 | External for k8s |
| API → OIDC IdP | egress | 443 | Discovery/token/JWKS |
| intel-worker → Radar/VulnCheck | egress | 443 | Token file mounts only on worker |
| evidence-signer → (none external required) | — | — | Signs via local key file |
| customer-runner → API | egress | 443 | Outbound only |
| PostgreSQL host publish | — | **none by default** | Hardened Compose |

Deny-by-default NetworkPolicies ship in the Helm chart with explicit allow rules.
