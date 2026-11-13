# Private release bundle

Generate from a merge commit on `main`. **Do not** push images/charts to a public registry.

## Contents checklist

- [ ] Pinned image references + digests
- [ ] Helm chart tarball (`helm package`)
- [ ] Hardened Compose files
- [ ] Configuration contract
- [ ] Runbooks (install/upgrade/rollback/backup/OIDC/runner/network)
- [ ] SBOMs (Syft or equivalent; record tool/version)
- [ ] Trivy vuln + secret + misconfig evidence
- [ ] Checksums (`sha256sum`)
- [ ] Release manifest + limitations
- [ ] Support/escalation placeholders clearly marked as placeholders

## Exclusions

Secrets, tokens, private keys, live dumps, `.env` from any environment.

## Limitations statement (required)

Phase 3F packaging is for controlled design-partner pilots. It does not constitute commercial production readiness, HA validation, SLA, support commitment, or compliance certification.
