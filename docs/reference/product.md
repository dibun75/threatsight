# Product Definition

ThreatSight 2 is an in-house **AI assurance platform**. It connects governance requirements and security controls to technical evidence and authorized adversarial validation.

## What it is

- A system of record for AI systems, controls, tests, evidence, verdicts, remediation, and retests.
- A deterministic assurance engine (from M3 onward) that evaluates control behavior against evidence.
- A human-governed workflow: extracted requirements and mappings are candidates until approved.
- A self-hosted product intended to run in Docker for local and enterprise deployment.

## What it is not

- A legal compliance certification engine.
- A generic GRC replacement.
- A generic vulnerability, HTTP, or network scanner.
- A jailbreak leaderboard or runtime AI firewall.
- An autonomous production attack platform.
- A security-news globe or news aggregator.
- A continuation of the ThreatSight 1.x scanner or UI.

## North star loop

```text
Requirement → Control → Test → Observe → Evidence → Verdict → Remediation → Retest → Assurance
```

The central object is the **Control**. Tests exist to produce evidence for a control. Verdicts are `PASS`, `FAIL`, or `INCONCLUSIVE`.

## Language rules

Use:

- "evidence supports"
- "gap identified"
- "human review required"

Do not use automated tests to claim that an organization is legally compliant.

## Current product slice

M15 is frozen as an architecture showcase: Overview leads with the cancel-order story; catalogs stay secondary until after AUTH-01. It does not add legal-compliance certification, live threat feeds, or a runtime firewall. Do not start M16+ without an internal sponsor.
