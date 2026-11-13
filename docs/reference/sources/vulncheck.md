# VulnCheck Community KEV — collection contract

Reviewed **2026-11-03** against official VulnCheck documentation only.

| Field | Value |
| --- | --- |
| Role | `exploitation_observation` |
| Account | Free Community at [console.vulncheck.com](https://console.vulncheck.com) |
| Dataset | VulnCheck KEV (Community). Distinct from CISA KEV, VulnCheck canaries, and XDB. |
| Auth | `Authorization: Bearer <token>` only (no query-string tokens in production) |
| API version | v3 |
| Primary endpoint | `GET https://api.vulncheck.com/v3/index/vulncheck-kev` (paginated JSON) |
| Focus query | `?cve=CVE-…&limit=100` |
| Backup endpoint | `GET /v3/backup/vulncheck-kev` returns a download URL — **not used** (avoids zip/file download) |
| Rate limit | Community ≈ 1000 req/min → HTTP 429 |
| Attribution | Prominent “VulnCheck KEV” attribution required in UI/metadata |
| Token expiry | Unused tokens expire after 30 days |
| Default | **Disabled** until operator installs a worker-only token file |
| Secret | Host path via `THREATSIGHT_VULNCHECK_TOKEN_PATH` → `/run/secrets/vulncheck_token` on `threatsight-intel-worker` only |
| Compose overlay | `docker-compose.vulncheck.yml` |

## Field mapping (official schema)

| Official field | ThreatSight handling |
| --- | --- |
| `cve[]` | Subject CVE(s); one document per CVE |
| `date_added` / `_timestamp` | published/updated times |
| `vulncheck_reported_exploitation[]` | Bounded citation metadata only; URLs not fetched |
| `reported_exploited_by_vulncheck_canaries` | If true → `exploitation_directly_observed` |
| VulnCheck KEV membership | `researcher_catalogued` (not media, not CISA) |
| `vulncheck_xdb[]` | Store xdb_id counts/ids only; never clone or download |
| `cisa_date_added` | Metadata flag only — **does not** set `government_catalogued` |

## Official docs reviewed

- https://docs.vulncheck.com/community/vulncheck-kev
- https://docs.vulncheck.com/community/vulncheck-kev/schema
- https://docs.vulncheck.com/getting-started/api-tokens
- https://docs.vulncheck.com/api/v3
- https://docs.vulncheck.com/community

Absence of a token must not block Siemens or media collectors.
