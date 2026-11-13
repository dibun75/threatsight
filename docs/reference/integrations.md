# Integrations

ThreatSight 2 does not replace a GRC platform. M8 ships exchange documents and HTTP extension points.

## GRC / Saidot-class exchange

`GET /api/v1/exports/grc-bundle.json` (`format: threatsight.grc.v1`) includes:

- AI systems
- requirements
- controls (assurance_status, latest_verdict)
- evidence
- findings

`connector` is always false. A future Saidot or similar adapter would consume this document; it is not implemented here.

## CI/CD regression

GitHub Actions workflow `.github/workflows/regression.yml`:

1. Isolated pytest (`THREATSIGHT_RUN_MIGRATIONS=false`)
2. `docker compose config` for lab and enterprise overlays

The full live suite remains:

```bash
make up
make test
```

That is the deployment gate. Do not wire CTRL-002 against production systems as a pipeline attack.

## What is not integrated

- ServiceNow / Jira / Slack
- OIDC SSO
- Billing
- Telemetry vendors (see observability.md)
