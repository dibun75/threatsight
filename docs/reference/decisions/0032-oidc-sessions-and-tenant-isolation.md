# ADR 0032: OIDC identities, opaque sessions, and tenant-owned workspaces

Status: Accepted

## Decision

Production authentication uses Entra-compatible authorization-code OIDC with PKCE S256. The API validates exact issuer, ID-token audience equal to the client ID, RS256 signature from keyed JWKS, `iat`/expiry/not-before, nonce, and authorized group mappings. Login state is bound to a browser flow cookie. ID tokens are exchanged for random application sessions; only SHA-256 session hashes are stored. New identities are not enrolled unless just-in-time provisioning is explicitly enabled or a membership already exists. Cookie writes require an allow-listed origin and CSRF token.

Canonical roles are `operator`, `auditor`, `workspace-admin`, and `platform-admin`. Legacy `reviewer` maps to `operator`; legacy `admin` maps to `workspace-admin`. Platform administration requires an explicit configured group and is never inferred.

Migration `0012_phase2_trust` creates the default tenant, owns every existing workspace by that tenant, creates identities, tenant memberships, identity-linked workspace memberships, OIDC flows, and revocable sessions. Production requires `auth_mode=oidc`; header/shared-token authentication exists only in explicit development mode.

## Consequences

Every Phase 2 resource must be tenant and workspace owned. Request dependencies compare the authenticated tenant to workspace ownership and resolve membership by immutable identity ID. Legacy M0–M15 global records are not yet isolated by those bindings; migrating them is separate work. A production deployment without complete HTTPS OIDC configuration, a public endpoint, and a redirect URI on an allowed origin refuses startup.
