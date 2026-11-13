# Exposure graph

Status: P2-11 reference model. Fixture relationships are not customer exposure findings.

The graph describes what normalized Microsoft, Meraki, and Junos records state and how those records relate inside one tenant and workspace. Path analysis reads a completed snapshot and does not change it. See [Exposure path analysis](./analysis.md). Correlation reads that snapshot and does not change it. See [Threat-to-asset correlation](./correlation.md).

The three Nordic Retail services and every fixture-derived row are synthetic and fixture_tested. They are not a real customer.

## Schema

Migration `0014_exposure_graph` adds only these tables. Phase 1 `business_services` is unchanged. Synthetic services are graph nodes, not rows in that table.

| Table | Purpose |
| --- | --- |
| `graph_snapshots` | One build. `building`, `completed`, `failed`, or `cancelled`. At most one `is_current` completed snapshot per workspace |
| `graph_nodes` | Typed records bound to a snapshot |
| `graph_edges` | Typed relationships bound to the same snapshot |
| `graph_observations` | Sanitized source assertions. Raw connector bodies are not stored |
| `graph_conflicts` | Preserved disagreements, gaps, and unsupported facts |
| `graph_service_memberships` | Direct membership of a node in a business service |

Every row carries `tenant_id` and `workspace_id`. Nodes and edges also carry snapshot, source key, type, connector, contract, source record, maturity, evidence mode, collection time, materialization time, freshness, confidence, limitations, and lifecycle.

Internal ids are random UUIDs. They are not derived from vendor ids and are not authorization.

## Node vocabulary

A field on a connector record does not become a node type. Unmapped kinds (`collection_status`, `collection_gap`, `capability`, `device_status`, `routing_instance`, `management_service`, and unknown kinds) stay observations, conflicts, or limitations.

| Type | Intended use |
| --- | --- |
| `business_service` | Synthetic or operator-declared service. Not a Phase 1 business-service row |
| `cloud_subscription` | Azure subscription identifier |
| `resource_group` | Azure resource group identifier |
| `cloud_resource` | Cloud resource that has no narrower type |
| `application_service` | App Service or equivalent application record |
| `database_service` | Managed database server record |
| `load_balancer` | Load balancer or application gateway. The Azure form is an attribute |
| `identity` | User or unclassified directory principal |
| `group` | Directory group |
| `service_principal` | Service principal |
| `role` | Directory role |
| `role_assignment` | Assignment record. Not proof that the privilege is effective |
| `network` | Virtual network or Meraki network |
| `subnet` | Subnet or VLAN |
| `public_address` | Address record keyed by the source record, never by the address text alone. Documentation addresses are not exposure findings |
| `network_interface` | NIC, uplink, or physical interface |
| `device` | Meraki or Junos device, keyed by the source device id |
| `logical_interface` | Interface whose source name contains a unit separator |
| `security_zone` | Junos security zone |
| `route` | Route or route summary |
| `security_policy` | Policy or NSG rule reference. Not a control verdict |
| `vpn` | VPN or tunnel record |
| `site` | Explicit site or organization container. A display name is not a site identity |
| `software_version` | Version derived from one device record. The version string is not an identity |

`connected_to` is not a node. `governed_by` is an edge and is unused by the reference fixture.

## Edge vocabulary

There is no untyped relationship. Direction is source to target.

| Type | Direction and meaning |
| --- | --- |
| `contains` | Parent record to child record when the source ids say so |
| `member_of` | Principal to group |
| `assigned_to` | Role assignment to principal or role. Configuration association, not effective privilege |
| `attached_to` | Interface or address record to the record that reported it |
| `connected_to` | Approved for an interface-to-network association. The fixture does not emit it |
| `routes_to` | Route record to the interface id it names |
| `in_zone` | Interface to a security zone when the zone id matches |
| `governed_by` | Approved for a resource-to-policy reference. Not effectiveness. The fixture uses policy reference edges instead |
| `permits_reference` | Policy to a referenced object when the action is `allow`. Not a permit verdict |
| `denies_reference` | Policy to a referenced object when the action is `deny`. Not a deny verdict |
| `peers_with` | Two records from different connectors that share `site_key` under `shared-site-key-v1`. The nodes stay separate |
| `depends_on` | Fixture allow-list only: the synthetic ordering app to its synthetic database. Not an exposure path |
| `serves` | Member with role `entry` to its business service. Manual |
| `administered_through` | Business service to a node with role `administration`. Manual. Limitation `not_a_reachability_finding` |
| `sourced_from` | Derived software-version node to the device record that stated the version |

## Evidence

| Mode | Meaning |
| --- | --- |
| `observed` | The source reported it as current operational state |
| `configured` | Present in configuration or inventory, not operationally proven |
| `inferred` | A deterministic rule derived it from source facts |
| `manual` | An authorized operator or the fixture definition asserted it |

Fixture and resource-graph records stay `configured` unless the source truth is `observed`. `fixture_tested` is maturity, not evidence. A record is `live_verified` only when its envelope mode is `live`, its envelope maturity is `live_verified`, and its truth is `live_verified`. The reference fixtures never meet that bar.

An inferred edge stores `derivation_rule`, `derivation_version`, the contributing source keys, limitations including `not_an_exposure_finding`, and confidence `derived`. Confidence is `stated`, `derived`, or `unknown`. It is not a risk score. No AI-generated edge is accepted as a fact.

## Canonicalization

- Source key is `connector_key:external_id`, unique inside a snapshot.
- Vendor ids are preserved. Names, display names, hostnames, addresses, serial-like text, and labels are not merge keys.
- The same vendor id in another tenant or workspace is a different node.
- Cross-source linking uses an explicit rule. `shared-site-key-v1` version `1` links different connectors only when both attributes equal `synth-site-` plus 1–40 lowercase letters, digits, or hyphens. It creates `peers_with` and does not collapse the nodes.
- Structural Azure containment uses the resource id (`azure-arm-prefix-v1`) or `associated_resource_id` (`same-connector-parent-v1`). A matching display name is not enough.
- If identity is ambiguous, both nodes remain and a conflict is stored.
- Disagreeing assertions stay as separate observations. The node lifecycle becomes `conflicting`. Neither assertion is overwritten.
- Repeating a build with the same inputs produces the same content hash. The same idempotency key returns the completed snapshot.
- Identifier attributes keep up to 500 characters. Display labels are sanitized to 80 characters, with controls and angle brackets removed. Identifiers that contain controls are rejected.

## Conflicts and lifecycle

Absence of an edge is not evidence that no relationship exists. Snapshots carry `absence_is_not_negative_evidence`.

| Conflict | Meaning |
| --- | --- |
| `configured_observed` | Admin and operational status both exist and differ |
| `ambiguous_identity` | Two connectors share a label and no deterministic rule linked them |
| `duplicate_address` | Two connectors report the same address text. They are not merged |
| `dangling_reference` | A source id points at a record that is not in the build |
| `unsupported` | The connector reported an unsupported or unmapped capability |
| `partial_omission` | A later partial collection did not include a previously materialized source key |
| `stale_source` | The record is marked stale or its collection time is older than 30 days |
| `conflicting_assertion` | The same source key arrived twice with different payloads |

Lifecycle is `active`, `stale`, `missing`, `superseded`, or `conflicting`. A partial rebuild copies omitted source keys forward as `missing`. It does not delete them and it does not keep their edges as active. Freshness is `fresh`, `stale`, or `untested`.

## Snapshots

A build locks the workspace, projects records, and commits the snapshot, nodes, edges, observations, conflicts, and memberships in one transaction. The previous current flag is cleared in that same transaction before the new snapshot becomes current. A failed or cancelled build rolls back and writes a non-current failure row. The previous completed snapshot stays current. List and read APIs return completed snapshots only. A building, failed, or cancelled id returns the same not-found response as an unknown id.

Bounds: 500 nodes, 1,000 edges, 1,000 observations, 500 conflicts, 200 memberships, 100 edges per node, 8 KiB of attributes, and 5 seconds. A completed idempotency key is unique per workspace. Builds are refused when the kill switch is on.

## Business services

The fixture defines three services: Customer ordering, Privileged administration, and Remote access and site connectivity. Membership roles are `entry`, `dependency`, `identity`, `network`, and `administration`. Fixture membership is manual and synthetic. An operator with `workspace-admin` or `platform-admin` may add a direct membership on the current snapshot. That write does not change connector node attributes. It is audited as `graph_member` / `added` with the role only.

## APIs

All routes are under `/api/v1/graph` and use the workspace context. Pagination defaults to 50 and allows 1–100. Ordering is by type, then source key.

| Method | Path | Behavior |
| --- | --- | --- |
| POST | `/builds` | Admin only. Body is an idempotency key plus either fixture `nordic-retail` or `partial`, or up to 10 succeeded job ids owned by the workspace |
| GET | `/snapshots` | Completed snapshots |
| GET | `/snapshots/current` | The current completed snapshot, or the uniform not-found response |
| GET | `/snapshots/{id}` | One completed snapshot. Incomplete and foreign ids are not found |
| GET | `/nodes` | Optional `node_type` from the vocabulary |
| GET | `/edges` | Optional `edge_type` from the vocabulary |
| GET | `/nodes/{id}` | The node and its direct neighborhood. Depth is fixed at 1. At most 50 edges |
| GET | `/nodes/{id}/provenance` | Observations, conflicts, maturity, and freshness |
| GET | `/services` | Business-service nodes on the current snapshot |
| GET | `/services/{id}/members` | Direct membership |
| POST | `/services/{id}/members` | Admin only. Manual membership |

Unknown types are rejected. There is no traversal language, field selection, or path search. Foreign objects and missing objects return `Graph object not found`.

## Reference fixture

`nordic-retail` projects 36 nodes, 35 edges, 32 observations, 9 conflicts, and 12 memberships. It includes Azure containment, Entra group and role assignment, Meraki organization/network/device/VLAN/VPN, Junos device/interface/zone/route/policy/VPN, the three services, one `shared-site-key-v1` link, one unresolved shared label and documentation address `203.0.113.50`, one admin-up/oper-down interface, one route collected in 2020, one partial rebuild that marks the omitted Meraki device `missing`, one dangling policy reference, and unsupported collection-gap and management-service records. Addresses are documentation or private ranges. The partial fixture is the same set without that Meraki device, plus a partial collection status.

A stored connector envelope can be materialized only when the job succeeded in the same tenant and workspace. Client-supplied node and edge bodies are rejected.

## Security review

| Threat | Control |
| --- | --- |
| IDOR and cross-tenant edges | Every query filters tenant and workspace. Edge endpoints are inserted from the same snapshot. A cross-workspace node id is not found |
| Source-id collision | Identity is tenant, workspace, snapshot, and source key. Equal vendor ids in two workspaces stay separate |
| Graph poisoning | Builds accept an allow-listed fixture name or workspace-owned succeeded job ids. Record bodies are not a client field |
| Mass assignment | Request models forbid extra fields. Verdict-like attribute names are dropped |
| Arbitrary types | Database checks and API filters reject types outside the vocabulary |
| Unbounded expansion | Node, edge, observation, conflict, membership, payload, and duration caps fail the build without publishing it |
| High-degree reads | Degree is capped at 100 during materialization. Neighborhood reads return at most 50 edges and say when they truncate |
| Malicious labels | Controls and angle brackets are removed from labels. Identifiers with controls fail the build. Audits store codes, not labels |
| Stale or replayed results | Stale collection time is stored. The same idempotency key returns the completed snapshot instead of writing a second current row |
| Publication race | The workspace row is locked. The previous current flag is cleared before the new one is set. A unique index allows one current snapshot |
| Cancellation race | Cancellation and the kill switch roll back the unpublished snapshot. The previous completed snapshot remains current |
| Provenance tampering | Observations come from normalized records. Manual membership does not rewrite node attributes |
| Inference presented as observation | Inferred edges require a rule, version, contributors, and `inferred` evidence. They are not stored as `observed` |
| Raw connector leakage | Graph rows store sanitized attributes only |
| Object enumeration | Missing, foreign, and incomplete snapshots share one not-found response |
| Deletion after partial collection | Omitted source keys are copied forward as `missing`. They are not hard-deleted |

## Verification

Reviewed 2026-10-30. Focused graph tests and the isolated API suite passed 258 tests and skipped 1. The suite used a disposable database and dropped it. Before the runtime migration, `backups/threatsight-20261030T204244Z.dump` matched its sha256 file and `pg_restore --list` listed the pre-migration catalog, including `alembic_version` and `threat_events`, and not `graph_snapshots`.

The preserved database is revision `0014_exposure_graph`. Graph tables are empty. No fixture rows were loaded. Counts remained 2,182 threat events, 2,182 relevance rows, 41 clusters, 9 sources, 1 business service, 1 radar triage row, 1 readiness link, 32 AI systems, and 33 controls. Health stayed `{"status":"ok","service":"threatsight-api","milestone":"M15"}`. Images stayed `threatsight-api:23f8def` and `threatsight-web:23f8def`.

No Python dependency was added. `pip-audit` and mypy are not installed, and no image was rebuilt, so no new dependency audit or image scan was run. Ruff passed on the graph package, migration, and tests.

## Rollback

Downgrade of `0014_exposure_graph` drops only the six graph tables, in foreign-key order, and leaves Phase 1 and Phase 2 execution tables in place. That downgrade is not a recovery path for image `threatsight-api:23f8def`. The image's newest Alembic revision is `0011_phase1`, so a database at `0013_connector_execution` still cannot start it. Downgrade through `0012_phase2_trust` or `0013_connector_execution` would delete tenant, identity, runner, job, and connector rows and was not done.

A recreate has to start from an image that contains `0014_exposure_graph`. Local image `threatsight-api:eabaac5` does. It was started against clone `threatsight_recover_eabaac5`, answered `/health`, and left the clone at `0014_exposure_graph`. The public API was not replaced. See [Deployment](./deployment.md).
