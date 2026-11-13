# Generic OIDC guide (enterprise default)

## Flow

- Authorization code + PKCE (`S256`)
- State + nonce bound to secure flow cookie
- Strict issuer / audience validation
- Callback URL allowlisted via CORS / redirect URI match
- Secure `__Host-` cookies in production HTTPS deployments
- Group claim → role mapping via configured group lists
- JIT provisioning optional (`THREATSIGHT_OIDC_JIT_PROVISIONING`)

## Pilot defaults

- `THREATSIGHT_AUTH_MODE=oidc`
- Prefer `THREATSIGHT_OIDC_CLIENT_SECRET_FILE`
- Local auth is break-glass only

## Disposable validation

Use an isolated Keycloak (or equivalent) **only** in disposable test infrastructure. Never point disposable clusters at production IdPs with production secrets.

## Recovery administrator

1. Temporarily enable local break-glass with a strong password on a localhost-only admin binding, **or**
2. Adjust IdP group membership and re-login

Document the chosen procedure in the customer runbook; do not leave break-glass enabled after recovery.
