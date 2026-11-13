# Observability Baseline

M0 provides operator-visible health and diagnosable logs. Vendor-specific APM and OTEL consumption of *agent* traces are later concerns.

## Logs

- API logs are structured JSON when `THREATSIGHT_LOG_JSON=true`.
- Each request receives an `X-Request-ID` (accepted from the client or generated).
- Log lines include `request_id`, `path`, `method`, and `status_code`.

## Health endpoints

| Path | Meaning |
| --- | --- |
| `GET /health` | Process liveness. No dependency checks. |
| `GET /ready` | Readiness. Checks Postgres. |
| `GET /api/v1/meta` | Product identity and milestone. |
| `GET /api/v1/security/status` | Sandbox, kill switch, CTRL-002 engine flag, discovery fetch flags. |
| `GET /api/v1/assurance/status` | Adapter, demo-agent mode, evaluator, scenarios. |
| `GET /api/v1/discovery/status` | Adapter, demo-site URL, source/asset/pending counts, crawl flags. |
| `GET /api/v1/frameworks/status` | Catalog version, completeness flag, mapped-item counts. |
| `GET /api/v1/threats/status` | Intel catalog flags, mapped-technique counts, no-attack/no-crawl flags. |
| `GET /api/v1/ops/status` | Deployment status, auth mode, checklist counts. |
| `GET /api/v1/showcase/status` | Showcase safety flags, freshness window, walkthrough. |
| `GET /api/v1/intelligence/status` | Provider, LLM availability, never-authorize flags. |
| `GET /api/v1/connectivity/status` | Passive ingest flags. Not a firewall. |

## Metrics and tracing

Not in M0. When added, prefer OpenTelemetry export without making a vendor mandatory.

## What this is not

This baseline is for operating ThreatSight itself. Target-agent tool traces belong in the M3 evidence envelope, not in API access logs.
