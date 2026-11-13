# API

The stable machine interface is OpenAPI 3 at `/openapi.json` when `THREATSIGHT_OPENAPI_ENABLED=true` (lab default). Swagger UI is `/docs`. The enterprise overlay turns both off unless you set the flag.

## Auth

| Mode | When | Behavior |
| --- | --- | --- |
| `local` | production-capable | Email and password. Anonymous API calls return 401. Identity comes from the server session. |
| `oidc` | production-capable enterprise federation | Authorization code with PKCE. Anonymous API calls return 401. |
| `development` | local development and tests | Header or configured token identity. Rejected when `THREATSIGHT_ENV=production`. |
| `public_demo` | isolated fixture mode | Fixed read-only `demo-viewer`. Rejected when `THREATSIGHT_ENV=production`. |

`/health` and `/ready` stay public. `/api/v1/auth/local/login`, activation, and reset accept the anonymous calls they need. Browser-supplied actor, role, workspace, and Cloudflare identity headers are ignored in `local` and `oidc`. A viewer remains read-only. Logout is allowed for every authenticated role and still requires the CSRF token.

## Extension points

| Area | Path | Notes |
| --- | --- | --- |
| Findings | `GET /api/v1/findings`, `GET /api/v1/exports/findings.json` | Status/severity filters on the live list |
| Evidence | `GET /api/v1/evidence`, `GET /api/v1/exports/evidence.json` | Includes integrity_hash when present |
| Controls | `GET /api/v1/controls`, `GET /api/v1/exports/controls.json` | Assurance status is technical, not legal |
| Audit | `GET /api/v1/audit`, `GET /api/v1/exports/audit.json` | Append-only |
| GRC bundle | `GET /api/v1/exports/grc-bundle.json` | `threatsight.grc.v1` exchange document |
| Control matrix | `GET /api/v1/exports/control-matrix.json` | Control, requirement, test, result, evidence, owner, framework, freshness |
| Showcase | `GET /api/v1/showcase/status`, `POST /api/v1/showcase/demo/bootstrap` | Labelled demo; AUTH-01 still needs `confirm_execution` |
| Dashboard | `GET /api/v1/dashboard` | Counts plus derived provenance (`data_origin`, `evidence_source`, `generated_by`, `last_updated`) |
| Ops | `GET /api/v1/ops/status` | Deployment visibility |
| Intelligence | `GET /api/v1/intelligence/status`, `GET/POST /api/v1/intelligence/explain` | Heuristic explain by default. LLM never authorizes. |
| Connectivity | `GET /api/v1/connectivity/status`, `POST/GET /api/v1/connectivity/events` | Passive traces. Not a firewall. |

Exports include `legal_compliance_claim: false`. They are not a live GRC connector.
