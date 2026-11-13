# Integrations: API tokens and alerts

Ported from the earlier agent-testing line and rebuilt for the enterprise platform's identities,
tenants and workspaces (migration `0032_api_tokens_and_alerts`).

## Read-only API tokens

A platform administrator creates tokens on **Integrations** (`/integrations`). A token looks like
`tsk_<prefix>_<secret>` and is shown once. Only its SHA-256 is stored.

```
curl -H "Authorization: Bearer tsk_..." https://<host>/api/v1/exports/findings.csv
```

- Tokens belong to an active member of the tenant and act with the read-only `auditor` role.
- They work for `GET`/`HEAD` only. Writes get 403. `/api/v1/auth/*` (except `/auth/token`) and
  `/api/v1/integrations/*` are refused, so a token can never mint tokens or read destinations.
- Revoking, or disabling the identity or tenant, stops a token within a minute (cache window).
- The web proxy forwards only a well-formed `tsk_` bearer; any other `Authorization` header is dropped.
- Power BI / Excel: use the CSV and JSON routes under `/api/v1/exports/`.

## Alerts

Administrators add destinations per workspace: signed webhook (HMAC-SHA256 in
`X-ThreatSight-Signature`), Slack, Microsoft Teams (Adaptive Card) and SIEM (syslog RFC 5424 with
CEF, UDP or TCP). Every destination has a **Send test** button; the last 50 deliveries are kept.

An alert fires when a readiness result has the outcome `failed_by_defined_check` (the named
allowlisted check returned its fail condition). Payloads say this is not a statement of compromise.
Delivery runs after the database commit, on a background thread, with three tries.

Notes:
- Destination URLs and signing secrets are stored in the database and masked in every view. Treat the
  database as holding secrets.
- In production, webhook URLs must be HTTPS to a public address and redirects are refused.
- Today the in-process reference path only produces `configured_not_observed`, so real FAIL alerts
  arrive once live runner results are published through the same service call
  (`alerts.notify_result`).
