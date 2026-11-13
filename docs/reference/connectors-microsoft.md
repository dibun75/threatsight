# Azure Resource Graph and Microsoft Entra connectors

Status: `fixture_tested` reference implementation
Reviewed: 2026-10-30
Maturity: not `live_verified`

These adapters collect a bounded read-only inventory for the synthetic Nordic Retail scenario. They run only on the registered customer runner, through the existing job, lease, cancellation, and kill-switch contracts. ThreatSight user login is a separate OIDC flow and is not the credential used for inventory.

No Azure subscription or Entra tenant is authorized. Microsoft API behavior, pagination-token shape, and customer permissions still require validation with a real design partner. A successful fixture run must not be described as live verification.

## Official contracts

Reviewed 2026-10-30:

- [Resource Graph resources query, API `2024-04-01`](https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources?view=rest-azureresourcegraph-resourcegraph-2024-04-01)
- [Resource Graph paging](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/paging-results)
- [Resource Graph permissions](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview)
- [Resource Graph operations](https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/operations/list?view=rest-azureresourcegraph-resourcegraph-2024-04-01)
- [Azure Reader role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general)
- [List Entra role assignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0)
- [Directory role read permission](https://learn.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0)
- [Microsoft Graph permission model](https://learn.microsoft.com/en-us/graph/permissions-overview)
- [Azure role assignments, API `2022-04-01`](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-subscription?view=rest-authorization-2022-04-01)

The implemented queries are constants. Clients cannot submit Kusto, Graph URLs, or Resource Graph continuation tokens. Resource Graph queries do not use `take`, `limit`, or `sample`, because those operators suppress `$skipToken`.

## Permissions

Authentication is the client-credentials grant against `https://login.microsoftonline.com/{microsoft-tenant-id}/oauth2/v2.0/token`. The Microsoft tenant id is configuration, not the ThreatSight tenant id.

### Azure Resource Graph

| Access | Required | If absent |
| --- | --- | --- |
| `Microsoft.ResourceGraph/resources/read` | Yes | The inventory job fails as permission denied. An empty result is not substituted. |
| Read on each configured subscription | Yes | Microsoft returns 403 when none of the explicit subscriptions are readable. Partial authorization is recorded as partial, not as a complete inventory. |
| Any write action, including resource changes, role changes, policy changes, or remediation | No | Not requested and not implemented. |

The built-in Reader role includes `*/read` and is sufficient, but it is broader than the two read actions above. Prefer a custom role limited to those reads when a design partner can grant it.

### Entra inventory

| Access | Required | If absent |
| --- | --- | --- |
| Application permission `RoleManagement.Read.Directory` for role definitions and active role assignments | Yes | The inventory job fails as permission denied. |
| Directory object read for principal type | No | Principal type stays `unknown`. `Directory.Read.All`, `User.Read.All`, and `Group.Read.All` are not requested. |
| `GroupMember.Read.All` for group expansion | No | Group-derived membership stays unsupported. A direct assignment to a group remains distinguishable from a transitive membership edge. |
| Privileged Identity Management schedule read | No | Eligible access is `unsupported`. Active assignments are not treated as a complete privilege picture. |
| `Microsoft.Authorization/roleAssignments/read` | No | Azure resource role context is `unsupported`. Entra role collection can still succeed. |

Privilege comes from the Graph `isPrivileged` boolean or from these built-in Azure role definition ids: Owner `8e3af657-a8ff-443c-a75c-2fe8c4bcb635`, Contributor `b24988ac-6180-42a0-ab88-20f7382dd24c`, User Access Administrator `18d7d88d-d35e-4fb5-a5c3-7773c20a72d9`, and Role Based Access Control Administrator `f58310d9-a9f6-439a-9e8d-f62e7b41a168`. A display name is never used to infer privilege. Other Azure role assignments are excluded and that exclusion is recorded.

## Retained fields

Records are stored on the workspace-owned job attempt. P2-08 does not write a graph. Retention follows the job record until a later retention policy exists.

Azure records may retain resource id, type, sanitized name, location, resource group, subscription id, non-secret tags, VM size, OS type, public IP address, associated resource id, subnet prefix, and NSG rule direction, access, protocol, port, source, and priority.

Entra records may retain role template id, the API privileged flag, assignment id, principal object id, scope, direct versus group basis, active versus eligible assignment type when a schedule is readable, principal type, service-principal application id, and transitive group membership ids.

## Excluded fields

The connectors drop mail, sign-in names, phone numbers, photos, job titles, departments, display names, password and key credentials, secret-shaped tags, raw resource property documents, connection strings, tokens, and client secrets. Malformed or non-UUID principal ids are not fetched. Resource names and tags are stripped of control characters and length-capped before storage.

`conflicting` is used when two source rows share an id and disagree. `unknown` is used for a missing privilege flag, a missing association, or a deleted principal. `unsupported` is used for a capability or optional permission the connector does not have. These queries do not expose a reliable per-resource change time, so the connectors do not emit `stale`.

## Live collection

Live mode is disabled unless `THREATSIGHT_MICROSOFT_LIVE` is `true` on the runner. The runner resolves `THREATSIGHT_MICROSOFT_CREDENTIALS` by secret-reference locator. Placeholder and short credentials are refused before any network call. Requests stay on `management.azure.com`, `graph.microsoft.com`, and `login.microsoftonline.com`, use HTTPS, ignore redirects, and stop after a bounded response size. A result is marked `live_verified` only when that explicit live collection finishes without truncation, rate limiting, or a rejected continuation. Ordinary tests do not set the flag.

Vendor continuation values that contain whitespace or a URL scheme are rejected. Graph next links must stay on `graph.microsoft.com` and may select only the fields the connector already requested. The runner then records a partial result instead of following an unapproved URL.

## Verification

On 2026-10-30 the preserved database stayed at Alembic revision `0013_connector_execution`. No new migration was required. The API suite passed 187 tests, including the connector, OIDC, and tenant-isolation tests. Threat content remained 2,182 events, 2,182 relevance rows, and 41 clusters. The suite also appended its existing labelled demo and test AI-system rows; it did not change threat, source, triage, or readiness rows. `ruff check` passed for the connector changes. The API image has no Ruff, mypy, or pip-audit installation, and no package dependency was added. The public API process is still the Phase 1 image and was not rebuilt.
