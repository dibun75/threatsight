# Threat-to-asset correlation

Status: P2-13. A match says a normalized advisory identifier may apply to a graph node. It is not an incident, a finding, or proof that an advisory applies when version evidence is incomplete.

P2-14 UI work has not started. No model call decides whether an advisory applies. Matching uses normalized identifiers only. Titles, summaries, and raw connector payloads are not scanned.

The preserved database stays at `0014_exposure_graph`. Migration `0016_threat_correlation` is repository and disposable-test only until an image that contains it is proven on a clone.

## What a run binds

Ruleset `p2-13.v1`. Comparator `numeric-dotted-v1`.

Each completed run stores the tenant, workspace, completed snapshot, threat-set fingerprint, ruleset version, alias-table digest, content hash, timestamps, maturity copied from the node, freshness, and source limitations. A run that fails, is cancelled, or hits the kill switch is stored and is not current. The previous completed run stays current.

A completed snapshot that is no longer the workspace's current snapshot can still be correlated. The run then carries `replayed_snapshot`. Threat events are the global normalized Phase 1 set, ordered by external id. The run records which set it used. Geography does not select assets.

## Match states

| State | Meaning |
| --- | --- |
| `confirmed_identifier_match` | The CVE and the CPE vendor, product, and version are equal, and the advisory range is an exact `=` pin. This is identifier equality only |
| `version_supported_candidate` | Vendor and product match and the asset version sits inside a complete advisory range |
| `possible_match` | The product matches and the version is missing, or a cloud service and scope match without a version range |
| `unknown` | A version, firmware train, or range cannot be ordered safely |
| `conflicting` | Two sources for the same CVE and asset disagree on the version relation |
| `not_applicable_by_evidence` | The asset version is outside a complete range |

No row is stored for an asset that did not match. Absence is not safety. The limitation `absence_is_not_safety` is on every stored result. These words are not states: safe, secure, compliant, compromised, exploitable, breached, protected, reachable, attacker.

Every result also carries `not_compromise`, `not_exploitability`, `not_packet_delivery`, `not_control_failure`, `not_remediation`, and `not_attacker_origin`.

## Rules

| Rule | Match |
| --- | --- |
| `cve-cpe-exact-v1` | Exact normalized CVE plus CPE vendor, product, and version, and an exact `=` pin |
| `cve-version-range-v1` | Canonical vendor and product, then a complete range |
| `vendor-product-alias-v1` | The same version outcomes after an approved alias |
| `meraki-firmware-v1` | Meraki firmware family with a numeric version inside a complete range. Otherwise `unknown` or `possible_match` |
| `junos-version-v1` | Junos text that this comparator cannot order stays `unknown` |
| `software-identifier-v1` | Exact PURL plus a version inside a complete range. A display name alone does not match |
| `cloud-service-advisory-v1` | The advisory and the node both name the same cloud service and scope. The provider alone does not match a tenant |

Vendor and product tokens are lowercase and limited to letters, digits, dot, underscore, and hyphen. CVE text is structural. A CPE must be `cpe:2.3:` with twelve colons and at most 80 characters. A version longer than 64 characters, with more than seven dots, or with a non-numeric part is not parsed and is not truncated into a shorter version.

A complete range has both a lower and an upper bound, or an exact `=` pin. A one-sided range is not completed by inventing the missing bound.

## Aliases

The alias table is workspace scoped, versioned, and written only by `workspace-admin` or `platform-admin`, with a reason, actor, and audit row. Connector attributes and match APIs cannot insert an alias. Reusing an alias for a different canonical vendor or product is rejected. The table stops at 100 rows.

## Business services

A matched asset is listed on a business service only by walking explicit `depends_on`, `serves`, `contains`, and `sourced_from` edges, plus service memberships. Depth is 4 and fan-out is 20. A cycle stops the walk and records `cycle_terminated`. The weaker evidence mode on the path is kept: inferred, then configured, then manual, then observed. Propagation means the service depends on a candidate-matched asset. It does not mean the service is compromised or exposed.

## Clusters, KEV, EPSS, and geography

Duplicate events that share a cluster and the same CVE and asset become one row. `source_count` is the number of contributing events. Every source key stays on the row. Conflicting version claims stay `conflicting`.

`known_exploited` means CISA lists the CVE. It does not mean this customer was attacked. The limitation is `kev_is_not_customer_attack`. EPSS is stored as the score and score date. It is a dated probability, not impact or proof. The limitation is `epss_is_dated_probability`. The two values are not combined into a score.

Authority jurisdiction, target country, victim country, infrastructure country, and prevalence country stay separate fields. None of them is stored as attacker origin. None of them selects an asset.

A source limitation `stale_source` on an event is copied onto the match as stale freshness.

## Operator review

Reviews do not delete the match, the event, or the graph. They do not change another workspace.

| Decision | Rule |
| --- | --- |
| `unreviewed` | No current review. This value is not stored |
| `accepted_relevant` | An admin accepted the match as relevant. It is still not an incident |
| `not_applicable` | An admin recorded a reason. The match remains |
| `needs_more_data` | An admin recorded a reason |
| `suppressed_until` | Requires a future expiry no more than 90 days out |

The actor is the authenticated subject. A reason is required and is plain text. History is append-only. A review applies to a later run only when the match key and evidence hash are unchanged. A changed hash returns the displayed state to `unreviewed` and adds `review_evidence_changed`. An expired suppression is not current and adds `review_expired`.

## APIs

All routes are under `/api/v1/correlation` and use the workspace scope. An object outside that scope returns `404` and `Correlation object not found`.

| Method | Path | Who |
| --- | --- | --- |
| `POST` | `/runs` | Admin. Body is `snapshot_id` and `idempotency_key` only |
| `GET` | `/runs` | Reader. Completed, failed, and cancelled rows |
| `GET` | `/current` | Reader. The completed current run |
| `GET` | `/matches` | Reader. Filters are state, CVE, source, asset, service, freshness, and review |
| `GET` | `/matches/{id}` | Reader. Explanation, provenance, and review state |
| `GET` | `/services` | Reader. Matches that name a business service |
| `POST` | `/matches/{id}/reviews` | Admin |
| `GET` | `/matches/{id}/reviews` | Reader |
| `GET` | `/rules` | Reader. Ruleset, states, and bounds |
| `POST` | `/aliases` | Admin |

Page size is at most 100. There is no query language and no alias creation on the match routes. Explanations are plain text. Event titles, summaries, and raw attributes are not returned.

## Bounds

| Bound | Value | Visible result |
| --- | --- | --- |
| Threat events | 500 | `event_limit` |
| Graph nodes | 500 | `node_limit` |
| Comparisons | 5,000 | `comparison_limit` |
| Matches per event | 20 | `match_limit` |
| Matches per asset | 20 | `match_limit` |
| Stored results | 200 | `match_limit` |
| Propagation depth | 4 | `propagation_depth` |
| Fan-out | 20 | `fanout_limit` |
| Execution | 2 seconds | The run is not published |
| Aliases | 100 | The write is rejected |
| Version length | 64 | The version stays unparsed |

A limit stores partial or unknown evidence. It does not drop a considered result without recording the limit.

## Synthetic fixture

`load_fixture("correlation")` is test-only. The public graph build still accepts `nordic-retail` and `partial`. Nordic counts are unchanged.

| Case | Result |
| --- | --- |
| CVE-2024-1001 on exact-widget | `confirmed_identifier_match`, propagated to customer ordering. KEV on the merged event is not a customer attack. Authority `US` and target `SE` stay separate |
| CVE-2024-1002 on range-widget | `version_supported_candidate`, stale source |
| CVE-2024-1003 on alias-widget | `vendor-product-alias-v1` after the approved alias |
| CVE-2024-2001 on the Meraki access point | `version_supported_candidate`, propagated to privileged administration |
| CVE-2024-3001 on the Junos software child | `unknown` because `23.4R1-synth` is not ordered |
| CVE-2024-1002 on missing-widget | `possible_match` with `missing_version` |
| CVE-2024-4001 | One `conflicting` row |
| CVE-2024-5001 | One row, `source_count` 2 |
| CVE-2024-6001 | `not_applicable_by_evidence` |
| Unrelated asset | No row |
| CVE-2024-7002 | Provider-only cloud text does not match |
| CVE-2024-7001 | `possible_match` where service and scope are both explicit |
| CVE-2024-8001 | PURL match |
| Oversized version | `unknown`. The explanation does not contain the submitted text |

## Security review

| Threat | Control |
| --- | --- |
| Cross-tenant correlation | Snapshot, match, review, and alias reads require the same tenant and workspace. A foreign snapshot is not found |
| Comparison denial of service | Event, node, comparison, match, depth, fan-out, and time bounds stop the run or mark it partial |
| Malicious CPE, PURL, or version | Structural checks and length caps. Oversized text is not sliced and parsed |
| Parser denial of service | No backtracking CVE or version expression. Dots and part length are capped |
| Alias poisoning | Admin audit only. A conflicting retarget is rejected. Connector input cannot write the table |
| Review tampering | Actor comes from the session. History is append-only. A changed evidence hash clears the displayed decision |
| Replayed snapshot | Allowed only for a completed snapshot in the same workspace, and labelled `replayed_snapshot` |
| Publication and cancellation races | One current run per workspace. A failed commit or a stop before completion leaves the previous current run |
| Object enumeration | Unknown and foreign ids share one not-found response |
| Mass assignment | Create bodies forbid extra fields. The client does not send the actor |
| Unsafe explanation | Fixed templates, then plain text |
| Provenance loss | Source key and parser version stay on the match |
| Duplicate amplification | One row per rule, CVE, and asset. Cluster duplicates increment `source_count` |
| Hidden conflict | Inside and outside relations become `conflicting` |
| Inference as observation | The weaker evidence mode on the path is stored |
| Suppression hiding new evidence | A new evidence hash or an expired suppression returns `unreviewed` |
