# Operator runbook (reference + pilot)

No step requires displaying a secret value.

## Daily

- [ ] `GET /health` on API (and web via ingress)
- [ ] Intel worker healthy; note collector freshness (Radar/VulnCheck last success)
- [ ] Signing backlog (`pending`/`leased` count) not growing unbounded
- [ ] Disk and Postgres size trend
- [ ] Tunnel / ingress up (do not restart cloudflared unless required)
- [ ] Failed login counts (ops metrics) — no emails in logs

## Weekly

- [ ] Local backup `-Fc` + checksum; encrypt if transferring
- [ ] Review one restore-to-clone drill monthly
- [ ] Certificate / OIDC client secret expiry calendar
- [ ] Token/key rotation schedule (Radar, VulnCheck, signing key, runner)
- [ ] Dependency/Trivy summary review

## Upgrade

1. Preflight (`deploy/scripts/upgrade_preflight.sh`)
2. Backup
3. Migration preview
4. Roll web/API; keep singleton workers orderly
5. Health verify
6. Retain previous images

Never auto-downgrade the database schema.

## Rollback

- Compatible app rollback if schema unchanged
- Else restore dump to clone, verify signatures with **retained** public key material
- Signing private key continuity is an operator concern

## Incident / escalation

- Placeholder contacts until design partner assigns people
- Capture request ids; redact secrets
- Safe shutdown: stop workers → API/web → database last

## Offboarding

Follow [offboarding.md](./offboarding.md).
