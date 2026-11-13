# Connectors and customer runner

## Permission matrix (pilot default)

| Source / plane | Default | Notes |
|----------------|---------|-------|
| Public intelligence collectors | On (reference) | Not customer private data |
| Azure / Entra connectors | Off until authorized | Least privilege app registration |
| Meraki / Junos / edge | Off until authorized | Read-only collection |
| Customer runner jobs | Off until installed | Outbound-only to control plane |
| Remediation / write-back | **Never** in Phase 3G | Explicitly out of scope |

## Customer runner

- Runs in **customer** infrastructure
- Holds runner credentials only
- Polls/claims jobs outbound; no inbound management port required
- Version compatibility documented in upgrade runbook
- See `deploy/runbooks/runner.md`

Pilot hypothesis: Azure/Entra + one edge source, read-only, human approval for actions.
