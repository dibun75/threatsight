# ADR 0043 — Customer-resident observation sensor

Status: Accepted for P3K-10 specification.

## Decision

Real customer observations are collected and minimized inside a customer-controlled data plane. The shared ThreatSight API never opens a connection to a customer network, appliance, sensor, SIEM, or packet source. A sensor uses the existing workspace-scoped customer-runner identity and durable job contract, initiates outbound HTTPS only, and exports only an allowlisted observation envelope after explicit customer authorization.

A sensor is not the public-intelligence worker. Public sources remain global and source-separated. Customer observations are tenant-private and cannot populate another workspace, an anonymous map, a benchmark, or a public feed.

## Authorization

Collection requires a customer-approved sensor policy naming the workspace, allowed source adapters, network scope, observation classes, retention, export fields, rate bounds, and authorization expiry. The runner verifies the policy locally before collection and on every job. Expired, revoked, mismatched, or unsigned policy fails closed. Active probing, packet capture, content inspection, remediation, and configuration writes are outside the default policy and require separate future decisions.

## Data boundary

Raw packets, payloads, full logs, credentials, private keys, authentication tokens, internal DNS answers, complete firewall configurations, and unrestricted IP histories remain local. The default export is a bounded summary: source adapter, observed time window, direction, protocol and port where authorized, pseudonymous local asset reference, public peer IP only when approved, counts, local evidence digest, collection maturity, and limitations.

The control plane stores no customer secret and no raw sensor payload. It may correlate the minimized envelope to workspace-owned assets and services. An observation is not automatically an attack, incident, compromise, attribution, exposure, or control-effectiveness verdict.

## Transport and resilience

The sensor establishes outbound TLS to the approved control-plane origin, authenticates with a short-lived rotatable runner credential, claims only jobs for its tenant and workspace, and uploads bounded idempotent envelopes. There is no inbound listener. A customer proxy is supported. When disconnected, the sensor stores an encrypted bounded queue locally, applies retention and back-pressure, and resumes without reordering or duplicating accepted envelopes. Offline customers may export a signed bundle for manual import.

## Security controls

The runtime is non-root, read-only, capability-dropped, resource-bounded, and independently kill-switch aware. Adapters use fixed read-only operations and explicit targets. Customer secrets are resolved locally from the customer secret manager. Logs exclude observation bodies and secrets. Every policy decision, collection, rejection, export, import, and deletion is auditable by identifier and digest.

## Consequences

ThreatSight can show real customer observation layers only after a live sensor is authorized and validated for that workspace. Until then, the product must say that customer telemetry is unavailable and keep public global observations and synthetic reference data visibly separate. P3K-10 defines the contract; it does not activate a live sensor or claim customer validation.
