# Customer-resident observation sensor contract

This specifies the first pilot boundary for customer telemetry. It reuses the existing outbound customer runner; it does not authorize a central collector or a new inbound service.

## Trust-boundary flow

1. A workspace administrator creates a sensor registration and time-bounded authorization policy.
2. A customer administrator installs the signed runner image and stores its one-time credential in the customer secret manager.
3. The runner polls the control plane over outbound HTTPS, validates the policy locally, and invokes only an allowlisted read-only adapter.
4. Raw observations remain in bounded local storage. A minimizer creates a versioned envelope and evidence digest.
5. The runner uploads the envelope through the durable job lease. The control plane validates scope, policy, schema, time, idempotency, and size before atomic publication.
6. Workspace reads show customer observations separately from public intelligence and synthetic data.

The control plane cannot reach the sensor, resolve its secrets, choose an undeclared target, or submit an arbitrary query.

## Envelope v1

The contract is `threatsight.customer-observation.v1`. Required fields are:

- envelope id and idempotency key;
- tenant, workspace, sensor, adapter, and authorization-policy identifiers;
- observation start/end and collection time in UTC;
- direction: inbound, outbound, east-west, or unknown;
- allowlisted observation type;
- normalized protocol and port when permitted;
- pseudonymous local asset reference;
- public peer address only when explicitly permitted;
- bounded count and unit;
- provenance, completeness, freshness, and limitations;
- canonical evidence digest and runner version.

Credentials, secrets, cookies, packet or message bodies, unrestricted headers, raw configuration, raw event documents, private keys, authentication artifacts, and undeclared free-form fields are forbidden. Unknown fields fail validation.

## Initial observation types

A pilot may enable firewall allow/deny summaries, VPN authentication summaries, IDS/IPS alert summaries with customer-approved rule identifiers, flow summaries for approved service boundaries, and existing read-only control-check results. Aggregate counts are the default. Individual public peers are disabled unless the policy enables them. Private addresses use workspace-owned pseudonymous asset references. An address does not establish attacker identity or geography.

## Bounds and publication

- one tenant and workspace per sensor identity;
- at most 1,000 summary rows and 256 KiB compressed per envelope;
- at most a five-minute window for stream summaries;
- at most a 24-hour encrypted local retry queue by default;
- at most seven days of exported summaries in a pilot unless the customer chooses less;
- fixed adapter rate limits and concurrency of one per target;
- duplicate envelope ids are idempotent;
- partial or failed publication never replaces the last completed snapshot.

Increasing a bound requires a reviewed policy version.

## Authorization policy

The signed policy contains its id and version, workspace, issuer, issue and expiry time, adapter and target selectors, permitted types and fields, interval and rate, maintenance window, export and retention choices, public-peer choice, and kill-switch state. The runner checks every job locally. Revocation, mismatch, expiry, clock uncertainty, unknown fields, missing signature, or unavailable kill-switch state stops collection and export.

## Identity, secrets, and local storage

Runner credentials are returned once, stored hashed by the control plane, workspace-scoped, rotatable, and revocable. Adapter credentials remain customer-local references in a customer vault, Key Vault, external secret, or root-owned file mount. They do not belong in environment values, command arguments, images, Git, logs, or jobs.

Local queues are encrypted with a customer-controlled key and bounded by bytes and age. Acknowledged data is removed oldest-first. Revocation stops collection and upload. Audit metadata may retain identifiers and digests without observation content. Offline customers may export a signed bundle for manual import.

## Product semantics

The UI says Live customer observation only when the sensor and policy are active, the adapter is live-validated, the envelope is fresh, and the workspace owns it. Otherwise it says unavailable, stale, partial, failed using last-known-good, or disabled. Public observations never become customer impact. Customer observations never become a confirmed incident without a separate human or evidence-backed incident decision.

## Pilot gates

Before design-partner activation: privacy/legal field review; customer policy and retention approval; image SBOM, scan, and signature; credential rotation/revocation/expiry and cross-workspace denial; proxy, outage, retry, idempotency, queue, and clock-skew tests; arbitrary-query rejection; packet/body/secret leakage tests; online/offline kill switch; upgrade/rollback rehearsal; UI review of provenance and limitations; and documented deletion and incident response.

P3K-10 defines this contract only. It does not deploy a sensor, connect a customer, or establish commercial validation.
