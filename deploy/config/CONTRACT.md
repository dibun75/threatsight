# ThreatSight production configuration contract

Version: `threatsight.config.v1`  
Applies to: `pilot-compose`, `pilot-kubernetes` (and `production` env)

Classifications:

| Class | Meaning |
| --- | --- |
| `required` | Must be set for the profile |
| `optional` | Has a safe default |
| `secret_file` | Path to a file; never log contents |
| `safe_env` | May appear in ConfigMaps / env |
| `generated` | Created by installer/operator tooling |
| `profile` | Profile-specific |
| `deprecated` | Accepted temporarily; warn |

## Core

| Setting | Class | Notes |
| --- | --- | --- |
| `THREATSIGHT_ENV` | required | Must be `production` for pilot profiles |
| `THREATSIGHT_DEPLOYMENT_PROFILE` | required | `reference` \| `pilot-compose` \| `pilot-kubernetes` |
| `THREATSIGHT_PUBLIC_ORIGIN` | required (pilot) | Canonical https origin, no path |
| `THREATSIGHT_DATABASE_URL` | secret_file preferred / safe_env discouraged | No `changeme-dev-only` |
| `THREATSIGHT_DATABASE_URL_FILE` | secret_file | Preferred over inline URL |
| `THREATSIGHT_AUTH_MODE` | required | Pilot: `oidc` (default). `local` = break-glass only |
| `THREATSIGHT_CORS_ORIGINS` | required | Explicit allow-list matching public origin |
| `THREATSIGHT_WEB_ORIGINS` | required (pilot) | Explicit write-origin allow-list |
| `THREATSIGHT_OPENAPI_ENABLED` | required | Must be `false` in production |
| `THREATSIGHT_SANDBOX_DEFAULT` | required | Must remain `true` |
| `THREATSIGHT_PUBLIC_DEMO` | required | Must be `false` in production |
| `THREATSIGHT_ALLOW_SYNTHETIC_LOADERS` | optional | Default `false` in pilot |

## OIDC (enterprise default)

| Setting | Class |
| --- | --- |
| `THREATSIGHT_OIDC_ISSUER` | required when auth=oidc |
| `THREATSIGHT_OIDC_AUDIENCE` | required |
| `THREATSIGHT_OIDC_CLIENT_ID` | required |
| `THREATSIGHT_OIDC_CLIENT_SECRET_FILE` | secret_file (preferred) |
| `THREATSIGHT_OIDC_CLIENT_SECRET` | deprecated for pilot (env still accepted; prefer file) |
| `THREATSIGHT_OIDC_AUTHORIZATION_ENDPOINT` | required (or filled via discovery) |
| `THREATSIGHT_OIDC_TOKEN_ENDPOINT` | required (or discovery) |
| `THREATSIGHT_OIDC_JWKS_URI` | required (or discovery) |
| `THREATSIGHT_OIDC_REDIRECT_URI` | required; must match CORS origin |
| `THREATSIGHT_OIDC_DISCOVERY_URL` | optional; issuer `/.well-known/openid-configuration` |
| Group mapping vars | optional |

## Intelligence / signing / runner

| Setting | Class | Mount boundary |
| --- | --- | --- |
| `THREATSIGHT_RADAR_TOKEN_FILE` | secret_file | intel-worker only |
| `THREATSIGHT_VULNCHECK_TOKEN_FILE` | secret_file | intel-worker only |
| `THREATSIGHT_EVIDENCE_SIGNING_KEY_FILE` | secret_file | evidence-signer only |
| Runner credential file | secret_file | customer-runner only |

## Fail-closed production rejects

- default / `changeme-dev-only` database password
- `development` or `public_demo` auth in production
- insecure cookie / missing HTTPS public origin in pilot
- missing public origin / unsafe write-origin allowlist
- unknown auth mode or deployment profile
- malformed or world-readable secret files (where detectable)
- OpenAPI enabled
- sandbox disabled

## Safe check

```bash
python deploy/scripts/config_check.py --env-file /path/to/.env
```

Prints classification and pass/fail **without** printing secret values.
