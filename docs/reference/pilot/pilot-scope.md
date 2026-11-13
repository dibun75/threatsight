# Recommended first pilot scope

## Shape

- One tenant, one workspace
- Three to five named business services
- Identity: Azure/Entra (generic OIDC)
- One edge source (Meraki **or** Junos) — read-only
- Customer runner outbound-only
- Selected public intelligence sources
- Manual readiness approval; accountable actions
- Evidence manifests + signing
- Optional response exercise
- Evaluation window: **4–6 weeks** as a hypothesis — **not** a contractual commitment

## Out of scope

- Autonomous remediation
- Multi-tenant SaaS hosting by ThreatSight
- Compliance certification
- HA / SLA
- Paid cloud resources provisioned by the vendor without authorization

## Success measures (observe; do not promise percentages)

- Inventory coverage of nominated services
- Evidence freshness for critical controls
- Relevant-threat matches reviewed
- False-positive / unknown rate (qualitative)
- Time to identify affected services after a new signal
- Actions assigned and closed with evidence quality
- Operator usefulness (interview)
- Executive comprehension after a short briefing

No percentage improvement claims without measured baseline evidence.
