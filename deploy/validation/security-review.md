# Phase 3F security review checklist

Evidence is produced by unit tests, Helm template guards, Trivy, and disposable acceptance scripts. Not a certification.

| Case | Gate |
|------|------|
| Secret rendered in Helm output | `helm_template_guard.sh` |
| Secret mounted into wrong pod | Helm template isolation asserts |
| Default password | `validate_runtime_security` / config tests |
| Insecure cookie | `__Host-` production cookie tests |
| Development auth in production | pilot profile reject |
| Forged OIDC claims | `test_phase2_trust` + `test_enterprise_oidc_matrix` |
| Callback manipulation | auth flow + return path tests |
| Cross-tenant role mapping | `tenant_matches` / membership tests |
| Migration privilege misuse | migrate Job separate; runtime role docs |
| Worker / signer concurrency | advisory lock + SKIP LOCKED |
| Writable root filesystem | Compose `read_only` + Helm `readOnlyRootFilesystem` |
| Privileged pod | securityContext defaults |
| Service-account token exposure | `automountServiceAccountToken: false` |
| Missing NetworkPolicy | chart default-deny + explicit flows |
| Public database service | no DB Service in chart; Compose ports `[]` |
| Backup containing secrets | backup excludes tokens/keys |
| Restore without signing key | documented; evidence verify fails closed |
| Malicious Helm value | values.schema.json + template guard |
| Command/argument injection | fixed Job commands |
| Unsafe ingress annotations | ingress disabled by default |
| SSRF through configuration | `endpoint_problem` / HTTPS checks |
| Downgrade data loss | no auto schema downgrade |
| Old image/schema incompatibility | upgrade preflight + rollback runbook |

No fixable HIGH/CRITICAL production-image finding is acceptable. No committed/rendered secret is acceptable.
