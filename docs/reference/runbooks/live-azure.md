# Azure Resource Graph live validation

Prerequisite: a design partner, a registered runner, and written authorization. None of those exist. Do not run this against a real subscription until they do. Fixture success does not change maturity.

## Before collection

- Connector key `azure.resource_graph`, runner image tag recorded, control-plane image tag recorded.
- Customer authorization names the tenant, subscriptions, window, and approvers.
- Permission is `Microsoft.ResourceGraph/resources/read` on those subscriptions. Prefer that custom role over the broader Reader role. No write action.
- Secret reference points at a customer-held credential. The value is not entered into ThreatSight.
- Target allowlist is the named subscriptions only.
- Expected records are resource id, type, location, and the tags the fixture contract already keeps. Excluded records include role definitions, policy bodies, and diagnostic content.
- Duration and bounds are the connector job limits already enforced: payload, time, retry, and concurrency. Stop if the kill switch is on, the lease expires, or the result is partial without an explanation.
- Rollback is revocation of the runner credential and disabling the connector instance.

## After collection

Review logs for secrets, compare expected and actual counts, and check provenance time. `live_verified` requires all ten conditions:

1. explicit customer authorization
2. successful authorized collection
3. permission review
4. normalized-record review
5. redaction review
6. provenance and freshness review
7. expected-versus-actual comparison
8. customer acceptance
9. an evidence record
10. no unresolved security defect

A successful HTTP call does not set `live_verified`. The product must not do that automatically. Known gap: Microsoft paging and permission errors are documented as partner validation, not as completed live proof.
