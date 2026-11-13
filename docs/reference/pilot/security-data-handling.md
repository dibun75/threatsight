# Security and data-handling summary

## Principles

- Least privilege mounts: Radar/VulnCheck tokens → intel worker only; signing key → signer only; OIDC secret → API only; runner credential → runner only
- Fail-closed production configuration for pilot profiles
- No autonomous remediation; sandbox default remains on
- Synthetic/reference data must be labelled; never presented as customer evidence
- Sessions: Secure + HttpOnly + SameSite; production uses `__Host-` cookies
- Secrets never in Helm values, images, Git, or demo scripts

## Data classes

| Class | Examples | Handling |
|-------|----------|----------|
| Public intelligence | KEV/EPSS/Radar-derived | May be shared; relevance is workspace-specific |
| Customer inventory | Services, tech, connectors | Tenant/workspace isolated |
| Evidence / signatures | Manifests, digests | Workspace-scoped; private key never exported |
| Auth | Sessions, OIDC tokens | Hashed/opaque where applicable; short-lived |

## Operator commitments

- Do not paste secrets into chat, tickets, or screenshots
- Rotate tokens/keys on a schedule (see operator runbook)
- Treat backup dumps as sensitive even when “public intel” dominates row counts
