# Identity / OIDC requirements (controlled pilot)

## Required

- Authorization-code flow (+ PKCE where applicable)
- Issuer discovery or explicit endpoints (HTTPS)
- Strict issuer + audience validation
- `state` + `nonce`; reject replay
- Callback allowlist matching public origin
- Secure `__Host-` cookies in production
- Group/claim → role mapping (operator / auditor / workspace-admin; platform-admin break-glass)
- Tenant/workspace membership mapping
- Logout + session expiry behavior
- Fail-closed startup for invalid pilot/production config
- Documented recovery administrator procedure

## Forbidden in pilot production

- Cloudflare-header authentication
- Development/reference-host auth mode
- Client secret in logs, Helm values, or rendered manifests

## Evidence in Phase 3G

Disposable Keycloak (+ local TLS) proves the browser path. Live reference may remain on local owner auth for guided demos until an explicit cutover.
