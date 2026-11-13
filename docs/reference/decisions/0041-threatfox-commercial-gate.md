# ADR 0041 — ThreatFox usage-entitlement gate

## Status

Accepted. Live collection is authorized for the operator's personal evaluation deployment. This does not cover resale, customer delivery, paid pilots, or another commercial/for-profit use.

## Decision

- Only the outbound intelligence worker may call `https://threatfox-api.abuse.ch/api/v1/`.
- The request is a bounded POST with `query=get_iocs` and `days=1`.
- Authentication is read from a mounted file and sent only as the `Auth-Key` header.
- The API, web, connector worker, runner, signer, and database never receive the key.
- Collection is disabled by default and fails closed unless `THREATSIGHT_THREATFOX_USAGE_MODE` is exactly `personal_evaluation` or `commercial_entitled`.
- `personal_evaluation` is allowed only for this operator-controlled, non-customer evaluation.
- Before ThreatSight is sold, used in a paid pilot, or offered to a customer, the operator must obtain the required enhanced paid entitlement or written authorization and change the mode to `commercial_entitled`.
- ThreatFox observations remain separate from Cloudflare routes, DShield signals, exploitation catalogs, customer exposure, and incidents.
- Raw responses, reporter identities, comments, credentials, and unbounded tags are not stored.

## Why

The official Community API requires an Auth-Key and states that commercial or for-profit use may require the enhanced paid API. The current use is personal evaluation, not commercial authorization. Technical access alone never authorizes a future commercial deployment.

## Activation gates

1. Usage mode and scope recorded by the operator.
2. Worker-only token file installed outside Git and images.
3. Fixture parser, secret-isolation, failure, and last-known-good tests pass.
4. A live canary succeeds without leaking the key.
5. Source attribution and limitations remain visible in the product.

The commercial gate must be revisited before any sale, paid pilot, customer demonstration using the feed, or customer-hosted deployment.
