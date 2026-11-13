# Exposure path analysis

Status: P2-12. A result is a rule outcome over one completed graph snapshot. It is not a finding, a packet path, or a threat match.

P2-13 correlation is separate and does not change path results. See [Threat-to-asset correlation](./correlation.md). P2-14 UI has not started. No model call selects paths, ranks evidence, or changes state.

## Result vocabulary

Ruleset `p2-12.v1`.

| State | Meaning |
| --- | --- |
| `supported_candidate` | The documented rule's required graph facts are present. This is not proof of delivery, use, or compromise |
| `unknown` | A required fact is missing, stale, or the bounded walk stopped |
| `conflicting` | Sources disagree, or an identity/address match was not merged |
| `unsupported` | The connector reported a capability it does not map |
| `not_evaluated` | Reserved. Version 1 writes no row when a rule's inputs are absent |

These words are not states and do not appear as conclusions: safe, secure, compliant, compromised, exploitable, breached, protected, reachable.

Every result carries these limitations: `not_packet_delivery`, `not_exploitability`, `not_compromise`, `not_control_effectiveness`, `not_compliance`, `not_threat_relevance`, `absence_is_not_safety`.

Maturity is copied from the contributing connector fact. `fixture_tested` is never stored as `live_verified`. `configured` is never rewritten as `observed`. Inferred edges stay `inferred`.

## Categories

| Category | Question the rule answers |
| --- | --- |
| `internet_exposure_candidate` | Does a business service have a public-address entry, and do route or policy facts join that entry to an application? |
| `management_plane_candidate` | Is a management interface or service present as configuration? |
| `privileged_identity_path` | Does a role assignment name an identity directly, or only through an unassigned group? |
| `cross_domain_service_path` | Does a service list network or VPN members across connectors, and were ambiguous records merged? |
| `contradiction_gap` | Do configured and observed values differ, or is a source stale, dangling, partial, or unsupported? |

## Rules

Shared bounds: depth 4, fan-out 20, stored paths 8, inspected nodes 200, execution 2 seconds. Ordering is type, then source key. A tie keeps that order. A bound that leaves the question unanswered stores `unknown` and `traversal_limit`. Cancellation, the kill switch, and the time bound abort the run. That run does not become current.

| Rule | Category | Required facts | Stop |
| --- | --- | --- | --- |
| `internet-entry-candidate-v1` | Internet candidate | Manual entry membership to a `public_address` | No row when that membership is absent |
| `internet-join-unknown-v1` | Internet candidate | Walk `contains`, `attached_to`, `depends_on`, `routes_to`, `in_zone`, `permits_reference`, `denies_reference` | `unknown` when no route or policy is visited. `traversal_limit` when the walk stops first |
| `management-configured-unknown-v1` | Management candidate | `network_interface` named `fxp0`, or unsupported `configuration_is_not_reachability` | `unknown` while evidence is `configured`. `unsupported` for the unmapped management service |
| `privileged-direct-assignment-v1` | Privileged path | `role_assignment` `assigned_to` both an identity and a role | `supported_candidate` with `direct_assignment` and `not_effective_privilege` |
| `privileged-transitive-assignment-v1` | Privileged path | `member_of` a group | `unknown` with `missing_group_assignment` when no assignment names that group |
| `cross-domain-service-v1` | Cross-domain path | Network-role membership to `vpn`, `network`, or `security_zone` | A completed neighborhood can be `supported_candidate`. An inferred `peers_with` stays inferred. A truncated neighborhood is `unknown` |
| `cross-source-unresolved-v1` | Cross-domain path | `ambiguous_identity` or `duplicate_address` | `conflicting` and `not_merged`. No edge is created |
| `contradiction-configured-observed-v1` | Gap | `configured_observed` | `conflicting`. Neither value is discarded |
| `gap-stale-input-v1` | Gap | `stale_source` | `unknown`, freshness `stale` |
| `gap-dangling-reference-v1` | Gap | `dangling_reference` | `unknown`, `missing_target` |
| `gap-unsupported-capability-v1` | Gap | `unsupported` | `unsupported` |
| `gap-partial-collection-v1` | Gap | `partial_omission` | `unknown`, `partial_collection` |

Explanation text is a fixed template. Labels and raw payloads are not copied into it. Angle brackets are stripped on output.

## Persistence

Migration `0015_exposure_analysis` adds `analysis_runs` and `analysis_results`. It revises `0014_exposure_graph`. Downgrade drops those two tables and leaves graph and Phase 1 tables in place.

A run stores tenant, workspace, snapshot, ruleset, deterministic `identity` (`sha256` of the snapshot content hash and ruleset), caller idempotency key, category rows, evidence modes, maturity, freshness, limitations, missing facts, contributing node and edge keys, and supersession. The same completed key and snapshot returns the same run. The same snapshot and identical facts return the current run. A key reused for a different snapshot is rejected. A failed, cancelled, or killed run stays non-current and leaves the previous completed run current. Publication is one transaction. The graph is not updated.

Completed snapshots only. Incomplete, failed, cancelled, and other-workspace snapshot ids return `Analysis object not found`.

This migration is not applied to the preserved database. The running API and `threatsight-api:eabaac5` contain revisions through `0014_exposure_graph` only. Applying `0015` there would make the next start fail. Disposable tests migrate their own databases.

## API

Workspace scoped under `/api/v1/analysis`. Starting a run requires `workspace-admin` or `platform-admin`. The body is `snapshot_id` and `idempotency_key` only.

| Method | Path | Behavior |
| --- | --- | --- |
| POST | `/runs` | Analyze one completed snapshot |
| GET | `/runs` | Completed, failed, and cancelled runs. Page size 1–100 |
| GET | `/current` | Current completed run |
| GET | `/results` | Filter by category, state, freshness, service id, or run id |
| GET | `/results/{id}` | One result and its contributing keys |
| GET | `/gaps` | Contradiction, unknown, conflicting, and unsupported rows |
| GET | `/rules` | Rule catalogue, bounds, and global limitations |

Missing and foreign objects use one not-found response. Responses do not include connector payloads or node attributes. There is no traversal expression, rule body, or threat-event query.

## Nordic fixture

The P2-11 Nordic Retail graph is unchanged. Analysis of that projection produces:

| Case | Rule | State | Limitation |
| --- | --- | --- | --- |
| Customer-ordering public entry | `internet-entry-candidate-v1` | `supported_candidate` | Manual membership to the public-address record. Not packet delivery |
| End-to-end join | `internet-join-unknown-v1` | `unknown` | Walk hits depth 4 before a route or policy can be confirmed or excluded |
| Direct privilege | `privileged-direct-assignment-v1` | `supported_candidate` | Assignment names the identity. Not an effective-privilege claim |
| Transitive privilege | `privileged-transitive-assignment-v1` | `unknown` | Group membership exists. No assignment names that group |
| Remote access / VPN | `cross-domain-service-v1` | `supported_candidate` or `unknown` | A completed neighborhood stays a candidate. A walk that hits depth 4 is `unknown`. `peers_with` remains inferred |
| Management interface | `management-configured-unknown-v1` | `unknown` | `fxp0` is configured. Operational state was not observed |
| Management service | `management-configured-unknown-v1` | `unsupported` | Connector recorded configuration only |
| Configured versus observed | `contradiction-configured-observed-v1` | `conflicting` | Admin and operational status differ |
| Stale route | `gap-stale-input-v1` | `unknown` | Collection time is outside the freshness window |
| Dangling policy reference | `gap-dangling-reference-v1` | `unknown` | Target identifier is absent |
| Unresolved cross-source pair | `cross-source-unresolved-v1` | `conflicting` | Shared label or address. Records stay separate |
| Bounded walk | `internet-join-unknown-v1` | `unknown` | `depth_limit` on the Nordic entry neighborhood |
| Cycle | Dedicated graph in `test_analysis_rules.py` | `unknown` | `cycle_terminated`. The Nordic fixture is not given an extra cycle |

The depth, fan-out, path-count, inspection, and time bounds are also exercised on small graphs in that test. Those graphs are not written into the fixture or the preserved database.

## Security review

| Risk | Control |
| --- | --- |
| Path explosion and high fan-out | Fan-out 20, path storage 8, depth 4, 200 inspected nodes |
| Algorithmic denial of service | Those caps plus a 2 second abort. No client traversal expression, regex, XPath, SQL, or rule code |
| Cycles | A node already on the path is not entered. The walk records `cycle_terminated` and returns |
| Tenant-crossing paths | Nodes, edges, conflicts, and memberships are loaded for one tenant, workspace, and snapshot. Foreign endpoints are dropped |
| Stale or replayed snapshots | The run stores the snapshot id and content identity. A failed run does not replace the current analysis. Historical completed runs remain readable in the same workspace |
| Rule or version tampering | The ruleset constant is server-side. Extra request fields are rejected |
| Result poisoning | Explanations are templates. Labels are not interpolated. Output strips controls and angle brackets |
| Evidence omission | A result without contributing node keys is rejected and not published |
| Inference shown as observation | Edge evidence is copied. Inferred stays inferred. Configured stays configured |
| Publication and cancellation races | Current-run replacement is one transaction. Cancel, kill switch, and time abort roll back and leave the previous current run in place |
| Mass assignment | The create body has two fields |
| Object enumeration | One not-found detail for missing, foreign, and incomplete objects |
| Unsafe explanation rendering | Fixed text plus sanitized source keys |
| Historical access | A result id is readable only with its completed run in the same tenant and workspace |

## Verification

Reviewed 2026-10-30. The isolated API suite passed 267 tests and skipped 1, including path analysis, graph, Microsoft, Meraki, Junos, connector, OIDC, and tenant-isolation tests. Migration downgrade of `0015_exposure_analysis` removed only the analysis tables. The suite used a disposable database and dropped it. The preserved database stayed at `0014_exposure_graph` with empty graph tables and no `analysis_runs` table. Counts remained 2,182 threat events, 2,182 relevance rows, 41 clusters, 9 sources, 1 business service, 1 radar triage row, 1 readiness link, 32 AI systems, and 33 controls. No fixture or analysis rows were loaded. Ruff passed. No package was added. `pip-audit`, mypy, `trivy`, and `grype` are not installed. The public API remained `threatsight-api:23f8def` and health stayed milestone M15.
