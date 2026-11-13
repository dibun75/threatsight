# Phase 2 Trust Foundation Threat Model

Status: Implemented reference boundary for P2-02–P2-04

## Protected assets and boundaries

Protected assets are tenant/workspace data, identity and role assignments, OIDC state/nonce/PKCE material, opaque sessions, connector secret references, runner credentials, normalized evidence, and audit history. The browser, identity-provider responses, connector payloads, uploaded documents, headers, object identifiers, and all cross-boundary network responses are untrusted.

The control plane terminates OIDC, derives identity and role server-side, resolves tenant/workspace membership, and is the only database writer. The future customer-resident runner is outbound-only and sends minimized records; it does not receive browser sessions or control-plane database credentials. Secrets remain references across the runner boundary.

## Data flows

```text
Browser
  -> OIDC login: state + nonce + PKCE S256
  -> Entra-compatible issuer: authorization code
  -> API callback: one-time state + code + verifier
  -> issuer token endpoint/JWKS: signed ID token
  -> API: exact issuer/audience/signature/expiry/nonce validation
  -> hashed opaque session cookie
  -> tenant membership -> workspace membership -> scoped query

Customer-resident runner (P2-05/P2-06)
  -> outbound registration/job lease
  -> local secret reference and read-only collection
  -> minimized normalized records + provenance/evidence hash
  -> tenant/workspace-owned control-plane rows

Junos collection (P2-10)
  -> runner holds the SSH key and dials only an approved on-premises target
  -> control plane stores normalized inventory, not XML, keys, or the raw configuration
  -> the API process does not open NETCONF

Graph materialization (P2-11)
  -> normalized fixture or same-workspace succeeded job envelope
  -> typed nodes, edges, observations, conflicts, and service membership
  -> no raw connector body, and no exposure or compromise verdict
```

## Threats and controls

| Threat | Required control |
| --- | --- |
| Forged or substituted identity | RS256 signature, exact issuer, ID-token audience equal to the OIDC client ID, keyed JWKS, `iat` and expiry, `azp` for multiple audiences |
| Login CSRF or callback replay | Random state stored as SHA-256 bound to a browser-only flow cookie, row lock, ten-minute expiry, one-time consumption |
| ID-token replay | Per-flow nonce and short token expiry; ID token is never an application session |
| Code interception | PKCE S256; verifier remains server-side |
| Session theft/database disclosure | Secure HttpOnly SameSite cookie in production; only SHA-256 opaque token hashes persisted |
| Cross-site cookie write | OIDC unsafe requests require an allow-listed `Origin` and a double-submit CSRF token. Just-in-time membership is off unless `THREATSIGHT_OIDC_JIT_PROVISIONING` is explicitly enabled |
| Expired/revoked session | Expiry and revocation checked on every request; inactive identity, inactive tenant, missing membership, or a session role that no longer equals the current membership fails closed and the mismatched session is revoked |
| Header spoofing | Production ignores `X-Actor`, `X-Role`, and bearer shared tokens |
| Privilege escalation | Canonical roles are server-derived from configured groups; `reviewer`→`operator`, `admin`→`workspace-admin`; no implicit `platform-admin` |
| Cross-tenant object access | Session tenant must equal workspace tenant; workspace membership is resolved by identity ID |
| Workspace-ID enumeration | Missing, foreign, or inactive workspaces return the same access-denied result |
| Runner compromise | Outbound-only registration, hashed rotatable credentials, workspace-locked leases, and tenant-scoped job claims |
| Meraki collection abuse | Fixed `https://api.meraki.com` origin, GET-only allow-listed paths, refused redirects, validated `Link` targets, explicit organization scope, no API key in stored records or errors, and no raw Dashboard body retention |
| Junos collection abuse | Runner-only NETCONF, no control-plane device connection, pinned host key, no trust-on-first-use, fixed read RPC templates, `defusedxml` bounds, and no raw transcript or secret retention |
| False evidence strength | Claim vocabulary below is mandatory and cannot be silently promoted |
| Graph poisoning or cross-tenant edges | Builds accept an allow-listed fixture or workspace-owned job ids. Queries and edges are tenant and workspace scoped. Inferred edges require a stored derivation rule |
| Partial collection treated as deletion | A later partial build marks omitted source keys missing and leaves the previous completed snapshot current if the build fails |

## Claim vocabulary

`synthetic`, `fixture_tested`, and `live_verified` describe validation maturity. `observed`, `configured`, `inferred`, and `manual` describe relationship provenance. `partial`, `stale`, `unknown`, `conflicting`, and `unsupported` describe limitations. Missing or contradictory data is `unknown`/`conflicting`, never safe. A configured path does not prove observed traffic, and a threat match does not prove compromise.

## Roles and break-glass

- `auditor`: read-only.
- `operator`: routine read/write work within assigned workspaces.
- `workspace-admin`: workspace administration, not platform authority.
- `platform-admin`: explicit configured IdP group only; reserved break-glass/platform operations.

Legacy `reviewer` and `admin` values are migrated/normalized for compatibility. Neither grants `platform-admin`.

## Residual risk and deferred work

P2-04 tenantizes the workspace ownership root and all future Phase 2 rows must carry tenant/workspace ownership. A 2026-10-30 review confirmed that legacy M0–M15 requirement, evidence, and system routes are still global to any authenticated writer; workspace resource bindings are not enforced there. That physical tenantization remains deferred and is not a current control. Phase 2 connector and job rows are tenant/workspace scoped. Graph rows from P2-11 and analysis rows from P2-12 are tenant/workspace scoped. An analysis result is a rule outcome, not a finding. Correlation rows from P2-13 are tenant/workspace scoped. A match is identifier evidence, not compromise, exposure, or attacker origin. The P2-14 interface renders API text and does not decide matches. P2-15 has not started.
