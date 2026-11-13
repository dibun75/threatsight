# Microsoft Entra live validation

Prerequisite: a design partner and written authorization. ThreatSight sign-in OIDC is a different application from this inventory credential. Do not reuse the sign-in secret for collection.

## Before collection

- Connector key `entra.identity`.
- Record runner and control-plane versions.
- Authorization names the Entra tenant, the window, and the approvers.
- Required application permission: `RoleManagement.Read.Directory`. `Directory.Read.All`, `User.Read.All`, and `Group.Read.All` are not requested. `GroupMember.Read.All` is optional and stays off unless the approvers add it.
- Test account is a dedicated application registration with that permission and no write role. Store it as a secret reference.
- Allowlist is the named tenant id. Expected records are role assignments and principal identifiers the connector already normalizes. Excluded: mailbox content, authentication methods, and raw Graph pages.
- Bounds are the job limits. Stop on kill switch, permission denial, or a partial page that cannot be explained.
- Revoke the application credential and the runner credential to roll back.

## Maturity

Use the same ten conditions as [live-azure.md](./live-azure.md). A token response is not acceptance. Principal type stays `unknown` when directory reads are absent, and that must be reviewed rather than hidden. Eligible PIM access remains unsupported.
