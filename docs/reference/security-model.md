# Security Model

This document is the runtime security baseline for M0–M15, Phase 0–1 Radar, and the Phase 2 trust foundation. The detailed Phase 2 analysis is in [threat-model.md](./threat-model.md).

## Principles

- Sandbox by default.
- Synthetic targets and data for demonstrations.
- Deterministic authorization and verdict path.
- LLMs never authorize attacks or network fetch.
- LLMs never issue the final security verdict.
- Explicit target authorization before any execution or discovery fetch.
- Complete audit trail.
- Evidence provenance and SHA-256 integrity on executed-run envelopes and discovered pages.
- No real destructive actions in the showcase environment.

## Runtime controls present in M3–M5

| Control | Behavior |
| --- | --- |
| `THREATSIGHT_SANDBOX_DEFAULT` | Must remain true or execution/fetch is refused. |
| `THREATSIGHT_KILL_SWITCH` | When true, CTRL-002 execution and discovery fetch are refused. |
| Execution engine | `ctrl002_tool_authorization` against the synthetic demo agent only. |
| Discovery engine | Authorized GET against the synthetic demo site only. |
| Target authorization | Demo targets are marked authorized with a 24-hour expiry on bootstrap. |
| Allow-list | Demo agent: `THREATSIGHT_DEMO_AGENT_URL`. Discovery: hostname of `THREATSIGHT_DEMO_SITE_URL`. |
| `confirm_execution` | Required on every CTRL-002 run and every discovery scan. |
| Rate limit | 30 confirmed executions and 20 discovery scans per process per minute. |
| Verdict authority | Domain invariants reject any evaluator other than `deterministic_policy`. |
| Document / HTML content | Treated as untrusted. Extraction cannot approve records, call tools, authorize fetch, or claim legal compliance. |
| Intelligence LLM | Optional. Schema-validated JSON. Never authorizes, never sets PASS/FAIL, never emits COMPLIANT. Fail closed to heuristic. Rate limit 20/minute. |
| Agent event ingest | Passive. Scoped to an existing AI system. Not a runtime firewall. |

## Scope of M3 execution

- Tools: synthetic `cancel_order` and `lookup_order`.
- Data: synthetic order `ORD-1001`.
- Network: Compose DNS `demo-agent`. The agent is not published on the host.
- No host filesystem, real email, destructive actions, or arbitrary external targets.

## Scope of M5 discovery

- Target: synthetic Northwind Copilot pages on Compose DNS `demo-site`. The site is not published on the host.
- No exploitation, port scanning, credential testing, or unrestricted internet crawl.
- robots.txt is honored. IP literals and non-allow-listed hosts are refused.

## Authentication and trusted proxy boundary

- `THREATSIGHT_AUTH_MODE=development` is explicit and may accept labelled `X-Actor` / `X-Role` attribution or the legacy private proxy token.
- Production accepts `THREATSIGHT_AUTH_MODE=local` or `oidc`. It rejects `development` and `public_demo`. OIDC remains the enterprise federation option. Local accounts use Argon2id and the revocable server session.
- Authorization-code OIDC uses one-time state, nonce, PKCE S256, exact issuer/audience, keyed RS256 signature, and expiry/not-before validation.
- Random opaque application sessions are HttpOnly/Secure/SameSite in production; only SHA-256 token hashes are stored and expiry/revocation is checked per request.
- Production ignores spoofed actor/role headers and shared bearer tokens.
- `auditor` is read-only; `operator`, `workspace-admin`, and explicitly mapped `platform-admin` may write. Legacy `reviewer`/`admin` normalize to `operator`/`workspace-admin`.
- Secrets stay in runtime environment/secret stores and never in images.

## Workspace boundary

- Every workspace belongs to a tenant. OIDC sessions carry one tenant and dependencies reject a workspace owned by another tenant before object lookup.
- Identity-linked tenant and workspace memberships are authoritative in OIDC mode.
- Radar resolves the authenticated server-derived subject to a workspace membership on every request.
- Official source contracts, events, vulnerability signals, and deterministic clusters are global records. A workspace can see an event only through its own relevance row.
- Organization profiles, relevance, saved views, triage, assignments, business services, readiness links, and workflow audit history are workspace owned and filtered by server-resolved membership.
- Controls, evidence, and systems can be selected from Radar only through an explicit workspace resource binding. This isolates the Phase 1 link surface but does not tenantize the underlying legacy record.
- Cross-workspace Radar reads and writes, saved-view IDs, triage, and readiness links are denied by live PostgreSQL integration tests. Auditors can read but cannot mutate workflow data.
- Workspace identity is not accepted from an untrusted browser header.
- Legacy M0–M15 tables are not fully tenantized. They must not be represented as providing complete enterprise tenant isolation.

## Fixed-source network boundary

- Radar synchronization uses fixed HTTPS adapters for CISA KEV, NSM, FIRST EPSS, CERT-SE, NCSC-FI, ENISA EUVD, and CERT-EU; callers cannot supply arbitrary source URLs.
- Adapters validate the exact HTTPS host, path, and query before following a redirect, enforce timeouts and an 8 MiB response limit, validate content types, and parse XML with entity expansion and external access disabled.
- SAMSIK and CERT-IS have no automated fetcher. Their APIs accept bounded metadata and canonical HTTPS links only within the registered authority domain.
- Source content is normalized to bounded plain text and structured values. It cannot become markup, credentials, authorization input, network destinations, or instructions.
- Discovery remains restricted to the configured demo-site hostname, rejects IP literals and non-allow-listed hosts, and validates redirect destinations rather than treating redirects as authorization.
- LLM output and uploaded content cannot authorize a network destination.
- Demo agent and demo site are Compose-internal only and have no host-published ports.

## Production fail-closed boundary

Production startup is refused unless OIDC mode and all issuer/audience/client/authorization/token/JWKS/redirect values are present, or when the database uses the development credential, CORS is empty/wildcard, or sandbox-by-default is disabled. API startup migrations are disabled in the production overlay; the one-shot migration service must complete first.

The web proxy owns the API token and trusted identity values on the private network. The browser receives neither the token nor authority to select its production subject, role, or workspace.

## Secrets

- `.env` is untracked.
- `.env.example` contains development placeholders only.
- Production credentials must never be committed or baked into images.

## Network

- Postgres is not required to be published in production deployments.
- The web container reaches the API on the compose network.
- CORS is an allow-list, not `*`.

## Non-goals

ThreatSight 2 will not become an autonomous unrestricted attack platform, a runtime AI firewall, or a generic scanner.

## Phase 2 connector execution boundary

- Secret-reference rows contain provider/locator metadata only. Ordinary API output redacts locators and recursively redacts secret-shaped connector, job, audit, diagnostic, and result fields.
- Runner credentials are high entropy, returned once, stored only as SHA-256 hashes, time bounded, rotatable, and revocable.
- Runner authentication is independent of browser OIDC and resolves the persisted runner tenant/workspace. Claims, health, progress, and results cannot cross that scope.
- Jobs use durable leases, bounded retries/backoff, per-workspace concurrency, idempotency, cancellation, attempts, dead-letter state, and workspace audit.
- The kill switch refuses enqueue and claim and is checked immediately before local or customer-runner execution.
- Connector SDK `v1` has no write capability. Payload/page/rate bounds and unsupported states fail explicitly.
- Runner and worker containers publish no host ports. Customer infrastructure receives no inbound control connection.

Phase 2 now provides the trust and execution foundation, not full physical tenantization of legacy M0–M15 tables, production high availability, customer-managed keys, or live-verified vendor connectors. Threat intelligence and manual readiness links remain informational until correlated with customer exposure and verified control evidence. Authority jurisdiction, target/victim geography, infrastructure location, and prevalence are separate concepts; none is inferred as attacker origin.
