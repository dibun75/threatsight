# Configuration and Secrets

## Strategy

- Runtime configuration is environment variables.
- The API reads `THREATSIGHT_*` settings through pydantic-settings.
- Compose interpolates the same values into containers.
- Secrets are never committed. `.env` is gitignored. `.env.example` is the documented template with development placeholders.
- Host ports are preferred values only. `make up` writes actual free ports to `.runtime-ports` (gitignored). See [DOCKER-HOST-RULES.md](./DOCKER-HOST-RULES.md).

## Required variables

| Variable | Purpose |
| --- | --- |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | Database bootstrap |
| `THREATSIGHT_DATABASE_URL` | API SQLAlchemy/psycopg URL |
| `THREATSIGHT_CORS_ORIGINS` | Browser origin allow-list (updated to the chosen web port) |
| `THREATSIGHT_SANDBOX_DEFAULT` | Security default |
| `THREATSIGHT_KILL_SWITCH` | Global execution refuse flag |
| `THREATSIGHT_RUN_MIGRATIONS` | Apply Alembic on API startup |
| `THREATSIGHT_LOG_JSON` / `THREATSIGHT_LOG_LEVEL` | Observability |
| `POSTGRES_PORT` | Preferred host port for Postgres (container `5432`) |
| `API_PORT` | Preferred host port for the API (container `8000`) |
| `WEB_PORT` | Preferred host port for the web UI (container `3000`) |
| `API_INTERNAL_URL` | Server-side web → API proxy target on the compose network |
| `COMPOSE_PROJECT_NAME` | Must remain `threatsight` |
| `THREATSIGHT_EXTRACTION_PROVIDER` | `heuristic` (default) or `openai` |
| `THREATSIGHT_INTELLIGENCE_PROVIDER` | `heuristic` (default) or `openai`. Empty API key fails closed to heuristic. |
| `THREATSIGHT_OPENAI_API_KEY` | Optional. Empty unless the OpenAI provider is selected |
| `THREATSIGHT_OPENAI_MODEL` | Remote model name when the OpenAI provider is used |
| `THREATSIGHT_OPENAI_BASE_URL` | Chat completions base URL |
| `THREATSIGHT_MAX_DOCUMENT_BYTES` | Upload cap (default 10485760) |
| `THREATSIGHT_ASSURANCE_ADAPTER` | `http` (live demo agent) or `inprocess` |
| `THREATSIGHT_DEMO_AGENT_URL` | Allow-listed synthetic agent, default `http://demo-agent:8090` |
| `THREATSIGHT_DISCOVERY_ADAPTER` | `http` (live demo site) or `inprocess` |
| `THREATSIGHT_API_TOKEN` | Optional only in development; production requires at least 32 characters. Held by API and web server, never browser code. |
| `THREATSIGHT_API_TOKEN_SUBJECT` | Server-derived subject for the trusted proxy token. |
| `THREATSIGHT_API_TOKEN_ROLE` | Server-derived role: `operator`, `reviewer`, `auditor`, or `admin`. |
| `API_INTERNAL_TOKEN` | Web server copy of the API token; Compose maps it from `THREATSIGHT_API_TOKEN`. |
| `THREATSIGHT_AUTH_MODE` | Explicit `local`, `oidc`, `development`, or `public_demo`. Production accepts only `local` or `oidc`. |
| `THREATSIGHT_OIDC_ISSUER` | Exact ID-token issuer. Use the tenant-specific Entra v2 issuer. |
| `THREATSIGHT_OIDC_AUDIENCE` | Retained for a future access-token audience. It is not used to validate ID tokens. |
| `THREATSIGHT_OIDC_JIT_PROVISIONING` | Default false. When false, OIDC login requires a pre-existing tenant membership. Enable only when IdP group assignment is the intended invitation. |
| `THREATSIGHT_OIDC_CLIENT_ID` / `THREATSIGHT_OIDC_CLIENT_SECRET` | Confidential OIDC client. The client ID is the ID-token audience. Inject the secret at runtime. |
| `THREATSIGHT_OIDC_AUTHORIZATION_ENDPOINT` / `THREATSIGHT_OIDC_TOKEN_ENDPOINT` | Tenant-specific authorization-code endpoints. |
| `THREATSIGHT_OIDC_JWKS_URI` | HTTPS issuer signing-key set. |
| `THREATSIGHT_OIDC_REDIRECT_URI` | Exact registered callback URI (`.../api/v1/auth/callback`). |
| `THREATSIGHT_OIDC_*_GROUPS` | Comma-separated exact group IDs for operator, auditor, workspace-admin, and platform-admin. Platform-admin must be explicit. |
| `THREATSIGHT_AUTH_SESSION_MINUTES` | Opaque session lifetime, 5–1440 minutes (default 480). |
| `THREATSIGHT_OPENAPI_ENABLED` | Lab default true. Enterprise overlay default false. |
| `THREATSIGHT_EVIDENCE_FRESH_DAYS` | Window for FRESH vs STALE (default 30). Not a risk score. |
| `THREATSIGHT_CONNECTOR_WORKSPACE_CONCURRENCY` | Maximum active connector leases per workspace (default 2, range 1–20). |
| `THREATSIGHT_CONNECTOR_LEASE_SECONDS` | Durable job lease duration (default 120, range 30–3600). |
| `THREATSIGHT_RUNNER_CREDENTIAL_HOURS` | Runner credential lifetime (default 24, maximum 168). |
| `THREATSIGHT_WORKER_POLL_SECONDS` | Worker/runner idle polling interval (default 2). |
| `THREATSIGHT_CONTROL_PLANE_URL` | Customer runner outbound control-plane URL. |
| `THREATSIGHT_RUNNER_CREDENTIAL` | One-time-disclosed runner credential; inject at runtime and rotate after exposure. |
| `THREATSIGHT_MICROSOFT_LIVE` | Opt-in Azure/Entra collection. Default false. Ordinary tests must not set it. |
| `THREATSIGHT_MICROSOFT_CREDENTIALS` | Runner-local JSON map from secret-reference locator to `{client_id, client_secret}`. Inject at runtime. Never commit it. |
| `THREATSIGHT_MERAKI_LIVE` | Opt-in Meraki collection. Default false. Ordinary tests must not set it. |
| `THREATSIGHT_MERAKI_CREDENTIALS` | Runner-local JSON map from secret-reference locator to `{api_key}`. Inject at runtime. Never commit it. |
| `THREATSIGHT_MERAKI_TEST_ORIGIN` | Test-only loopback origin. Honored only when `THREATSIGHT_ENV` is `development` or `test` and the value is `http://127.0.0.1` with an optional port. Ignored otherwise. Not a customer setting. |
| `THREATSIGHT_JUNOS_LIVE` | Opt-in Junos collection. Default false. Ordinary tests must not set it. This build still refuses to open NETCONF. |
| `THREATSIGHT_JUNOS_CREDENTIALS` | Runner-local JSON map from secret-reference locator to `{username, private_key}`. Inject at runtime. Never commit it. |

## Local development

```bash
cp .env.example .env
make up
make ports
```

Change the Postgres password before any shared or persistent environment. The example password is for single-developer Docker only.

Development header identity is accepted only when `THREATSIGHT_AUTH_MODE=development`. Never use that mode on a shared or production deployment. Production accepts `local` or `oidc` and rejects `development` and `public_demo`. `local` uses Argon2id passwords and the same hashed revocable session. `oidc` uses authorization code with PKCE. Both use an HttpOnly session cookie, a readable CSRF cookie, and ignore browser-supplied actor, role, workspace, and Cloudflare identity headers. The web service must receive `THREATSIGHT_AUTH_MODE`. In `oidc` mode it also needs `THREATSIGHT_OIDC_AUTHORIZATION_ENDPOINT` so it can forward only that login redirect.

`public_demo` is a separate mode. It requires `THREATSIGHT_PUBLIC_DEMO=true` and refuses to start when `THREATSIGHT_ENV=production` or when the flag is absent. Every request is the fixed subject `demo-viewer` with role `viewer`. That role cannot mutate. Request headers, cookies, query parameters, and Cloudflare Access headers do not select another actor or workspace. The designated workspace must be classified `synthetic_demo`. `/ready` returns unavailable if that workspace has live-verified connector data, an enabled runner, an unrevoked runner credential, or a secret locator outside the `local` and `fixture` schemes. The public rate limit is 600 requests per 60 seconds in one process. Graph, analysis, and correlation routes also share a separate budget of 60 requests per 60 seconds. A refusal includes `Retry-After: 60`. The limit does not use a client IP and it is not distributed protection. API responses are not stored. HTML uses `Cache-Control: no-cache`. Static Next assets may be cached as immutable. Operational logs record method, path, status, and a request id. They do not record query strings or authorization values. No analytics service is configured.

## Image rules

- Do not `COPY .env` into images.
- Do not bake credentials into `Dockerfile` `ENV` lines.
- Production deployments must inject secrets at runtime.
- Connector credentials are never supplied through connector configuration. Configure a metadata-only secret reference whose provider resolves the value in the customer runner or approved secret manager.
