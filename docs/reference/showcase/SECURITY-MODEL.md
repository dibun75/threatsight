# Showcase security model

Bounds that remain true during the Nordic Retail demonstration.

## Claims we never make

- Legal compliance
- Certification
- Replacement of a GRC platform
- Live enterprise discovery

`legal_compliance_claim` is always false. `COMPLIANT` is not a valid assurance status.

## Runtime defaults

| Control | Behavior |
| --- | --- |
| Sandbox | Must remain true or CTRL-002 / discovery fetch is refused |
| Kill switch | When true, execution and fetch are refused |
| `confirm_execution` | Required for AUTH-01/AUTH-02 and discovery scans |
| Verdict authority | `deterministic_policy` only. An LLM cannot issue the verdict |
| Targets | Synthetic demo agent and demo site on Compose DNS, unpublished on the host |
| Evidence | SHA-256 on executed-run envelopes |
| Audit | Append-only mutation log |
| Auth | Lab-open unless `THREATSIGHT_API_TOKEN` is set. Auditor is GET-only. Not SSO |

## Scenario target

- Company framing: Nordic Retail AS
- Inventory: labelled **Order support demo** in `lab`
- Tools: synthetic `cancel_order` / `lookup_order`
- Data: synthetic order `ORD-1001`
- No host filesystem, real email, or arbitrary external targets

Full baseline: [../security-model.md](../security-model.md).
