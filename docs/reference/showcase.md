# Showcase

Enterprise demonstration package for ThreatSight 2. Presentation only. No new engines.

ThreatSight is an AI assurance platform combining governance, evidence management, framework mapping, and deterministic validation of AI workflows.

| Document | Use |
| --- | --- |
| [EXECUTIVE-OVERVIEW.md](./showcase/EXECUTIVE-OVERVIEW.md) | Problem, solution, Nordic Retail scenario |
| [DEMO-SCRIPT.md](./showcase/DEMO-SCRIPT.md) | Ten-minute presenter path |
| [ARCHITECTURE.md](./showcase/ARCHITECTURE.md) | Layers and Docker diagram |
| [SECURITY-MODEL.md](./showcase/SECURITY-MODEL.md) | Bounds and non-claims |

## Five-minute path

```bash
cp .env.example .env
make up
make ports
```

Open the web origin (preferred `http://localhost:3000`, or the port in `.runtime-ports`).

1. Read Overview. If empty, onboarding explains the problem and solution. Zeros are honest. Default view is the labelled Nordic Retail showcase.
2. Open `/showcase`. Nordic Retail AS / Customer Support AI Assistant. Confirm **Load labelled demo**. **Reset labelled showcase** deletes only showcase-origin rows.
3. **Customer Support AI Assistant** is the in-scope system. **Order support demo** is the technical identifier, not a second enterprise system. Follow FAIL → evidence → remediate → retest.
4. Optionally confirm AUTH-01 for a live CTRL-002 FAIL. It does not auto-attack.

Reset: [troubleshooting.md](./troubleshooting.md#reset-the-demo).

## What this is not

- Legal compliance or certification
- A GRC replacement
- Live enterprise discovery
- An unrestricted scanner or exploit engine

`legal_compliance_claim` is always false. Synthetic demo data is labelled.
