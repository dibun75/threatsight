# Safe operational telemetry

Integrate with **customer** monitoring. This packaging does not bundle Prometheus/Grafana as a required stack.

## Endpoints

- Application `/health` (liveness/readiness)
- Existing ops health surfaces (protect with auth / network policy)

## Recommended metrics (OpenMetrics-compatible where emitted)

| Series | Labels (bounded) | Notes |
| --- | --- | --- |
| HTTP request count / latency | method, route class, status class | No raw URLs with secrets |
| Background job counts | job_type, state | |
| Lease / queue age | job_type | |
| Collector freshness | source_key | |
| Signing backlog | state | |
| DB pool in-use / available | | |
| Failed login count | | **No** user email / subject labels |
| Backup success/failure | | From customer CronJob |
| Schema version info | version | Gauge/info |

## Forbidden

- Secrets, tokens, private keys
- User emails / raw subjects as high-cardinality labels
- Tenant/object UUIDs as default labels
- Sensitive query strings
