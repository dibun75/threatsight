# Executive overview

ThreatSight 2 is a self-hosted **AI assurance** architecture prototype. It helps an organization govern and technically validate AI systems it already operates — with evidence, not vibes.

## Opening claim (say this first)

We proved a support AI could cancel another customer’s order. We blocked it. We retested. Here is the evidence hash.

Model narration is not a control.

## Problem

Organizations deploy AI systems faster than they can govern and validate them. An assistant that answers questions may also change orders.

## Solution

ThreatSight connects:

```text
AI systems
→ requirements
→ controls
→ evidence
→ assurance testing
→ findings
→ remediation
→ retest
```

The labelled showcase uses **Nordic Retail AS** and a **Customer Support AI Assistant**. The inventory row is the existing synthetic **Order support demo**. CTRL-002 is the control: AI agents must not execute unauthorized business operations.

## What a reviewer will see

1. Initial AUTH-01 test **FAIL**s when unauthorized `cancel_order` completes.
2. Evidence is a hashed observation envelope.
3. Gateway remediation is an explicit operator action.
4. AUTH-02 retest **PASS**es when the unauthorized action is denied.

Synthetic data is labelled. Discovery is an allow-listed lab site. Verdicts are `PASS`, `FAIL`, or `INCONCLUSIVE`.

## Audience

Security architects, AI platform owners, risk/CISO staff. Narrated demo. Not a self-serve board pack.

## What this is not

- Legal compliance or certification
- A GRC platform replacement
- Live enterprise discovery
- An unrestricted scanner, exploit engine, or runtime firewall
- A competitor to ChatGPT / Promptfoo / Vanta — different job

`legal_compliance_claim` is always false.

**Status:** frozen at M15 as a finished thesis with a working lab. Do not start later milestones without an internal sponsor.

Start: [DEMO-SCRIPT.md](./DEMO-SCRIPT.md). Architecture: [ARCHITECTURE.md](./ARCHITECTURE.md). Security bounds: [SECURITY-MODEL.md](./SECURITY-MODEL.md).
