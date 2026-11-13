# ThreatSight 2 — Feature Register

**Status:** Product blueprint  
**Repository:** `dibun75/threatsight`
**Last updated:** 2026-08-28  

This document is the authoritative feature register for ThreatSight 2. It captures ideas discussed during the 2.0 research phase so they are not lost. A feature being listed does **not** mean it is approved for implementation.

## Product North Star

ThreatSight 2 is an **AI assurance platform** for enterprises. It connects governance requirements and security controls to technical evidence and adversarial validation.

Core loop:

**Requirement → Control → Test → Observe → Evidence → Verdict → Remediation → Retest → Assurance**

The product should be useful as an **in-house enterprise deployment** and strong enough to demonstrate enterprise architecture, AI security, governance, compliance engineering, deterministic assurance, and polished product design.

## Feature Status

- **NOW** — approved for the current product foundation.
- **NEXT** — expected after the foundation is stable.
- **FUTURE** — valuable but deliberately deferred.
- **RESEARCH** — needs validation before implementation.
- **OUT** — explicitly outside the product boundary.

---

# 1. AI Governance & Assurance

## 1.1 AI System Registry — NOW

Register AI systems/agents with:

- system name and owner
- business purpose
- environment
- tools, data categories, and users/subjects (M13 profile)
- passive agent traces (M13; not a firewall)
- risk classification
- lifecycle/status
- version history
- responsible owner
- evidence and controls

## 1.2 Governance Requirement Ingestion — NOW

Ingest enterprise documents and extract candidate AI-governance requirements.

Supported sources should eventually include:

- PDF
- DOCX
- Markdown/text
- policies
- AI system descriptions
- security standards
- DPIAs
- vendor documentation
- architecture documents

AI extraction must produce **candidate requirements**, not silently declare legal obligations.

Every extracted requirement should retain:

- source document
- page/section reference where available
- extracted text
- confidence
- reviewer status
- version

## 1.3 Human Approval of Requirements — NOW

A human must be able to approve, reject, edit, or defer AI-extracted requirements.

No LLM-generated requirement becomes an authoritative control automatically.

## 1.4 Control Library — NOW/NEXT

Controls are the central assurance object.

Example:

```text
CTRL-002
Tool authorization must be enforced outside the model.

Expected: unauthorized cancellation is denied.
Evidence: intercepted tool trace.
Test: AUTH-01.
Status: PASS / FAIL / INCONCLUSIVE.
```

Controls should support:

- owner
- severity
- requirement linkage
- evidence
- tests
- status
- remediation
- retest history
- framework mappings
- applicability
- review date

## 1.5 Governance Framework Mapping — NOW

Map requirements and controls to recognized frameworks/regulations as **informational mappings**, including:

- EU AI Act
- GDPR
- NIST AI RMF
- ISO/IEC 42001
- OWASP guidance
- MITRE ATLAS
- other jurisdiction-specific frameworks where useful

M6 ships a curated, incomplete catalog with public locators and coverage derived from mapped control assurance statuses.

**Never claim that a test result alone proves legal compliance.**

## 1.6 Compliance / Assurance Report — FUTURE

Generate an evidence-backed report showing:

- applicable requirements
- mapped controls
- evidence available
- controls tested
- controls not tested
- gaps
- human-review items
- stale evidence

Use language such as **"evidence supports"**, **"gap identified"**, and **"human review required"**, not legal conclusions.

---

# 2. AI Security Assurance

## 2.1 Control Validation Engine — NOW

The validated ThreatSight 2 research capability.

Workflow:

1. declare control
2. bind target/configuration
3. execute authorized adversarial scenario
4. observe tool behavior
5. evaluate completed impact deterministically
6. produce evidence
7. recommend control-path remediation
8. retest

## 2.2 Deterministic Verdicts — NOW

Supported verdicts:

- PASS
- FAIL
- INCONCLUSIVE

The LLM must never be the final security authority.

## 2.3 Tool Authorization Testing — NOW

M3 ships CTRL-002 only: AUTH-01 unauthorized `cancel_order` and AUTH-02 authorized owner cancel against the synthetic demo agent.

Later candidates in this family, not implemented:

- additional high-impact tools
- approval requirements
- tenant isolation

## 2.4 Evidence & Trace Envelope — NOW

Capture, where available:

- model/provider
- agent version
- configuration
- scenario
- tool name
- tool arguments
- authorization decision
- policy decision
- tool result
- completed side effect
- timestamps
- evidence hash

Evidence must be reproducible and tamper-evident.

## 2.5 Before/After Validation — NOW

Compare secure and candidate configurations.

Example:

```text
FAIL → gateway policy enabled → PASS
```

Retest must be a first-class event rather than an informal rerun.

## 2.6 Control Coverage — NEXT

Show:

- tested controls
- untested controls
- stale controls
- failed controls
- inconclusive controls
- coverage by AI system
- coverage by risk

## 2.7 Additional Control Families — FUTURE

Potential families include:

- tool authorization
- tenant isolation
- sensitive-data disclosure
- human approval
- excessive agency
- data exfiltration
- privilege escalation
- unsafe external actions
- model/tool trust-boundary violations

Each new family must be validated against real agent behavior before being promoted.

## 2.8 RAG Security Testing — RESEARCH

Earlier 2.0 research proposed RAG attacks. Do not implement merely because they were proposed.

Potential future coverage:

- indirect prompt injection
- poisoned retrieval content
- cross-tenant retrieval
- unauthorized document access
- sensitive-data disclosure

## 2.9 MCP Security Testing — RESEARCH

Potential future coverage:

- malicious tool metadata
- tool poisoning
- authorization boundary failures
- cross-server trust violations
- unsafe tool invocation

This remains subordinate to the validated control-assurance wedge.

## 2.10 Regression Testing — NEXT

Run the same controls after:

- model changes
- prompt changes
- tool changes
- gateway/policy changes
- agent version changes
- deployment changes

Produce a historical control trajectory.

---

# 3. AI Governance + Security Relationship

## 3.1 Requirement → Control → Test Traceability — NOW/NEXT

A management-facing trace should answer:

> Why does this test exist, what requirement does it support, and what evidence proves the current state?

```text
Regulatory / Policy Requirement
            ↓
         Control
            ↓
          Test
            ↓
         Evidence
            ↓
        Verdict
            ↓
       Remediation
            ↓
         Retest
```

This is the central enterprise story of ThreatSight 2.

## 3.2 Evidence Reuse — NEXT

One piece of evidence may support multiple controls, while preserving provenance.

## 3.3 Evidence Freshness — NEXT

Track when evidence was collected and when it becomes stale.

---

# 4. Document & URL Intelligence

## 4.1 Document Upload — NOW

Users can upload governance, security, architecture, and AI-system documents.

The system extracts candidate requirements and evidence references.

## 4.2 URL Ingestion — NOW

Accept an authorized, allow-listed URL and retrieve relevant public documentation from the synthetic demo site.

M5 ships this slice against Compose DNS `demo-site` only. Arbitrary internet URLs are refused.

Security controls prevent SSRF and unauthorized access: http(s) only, no IP literals, robots.txt, `confirm_execution`, sandbox default, kill switch, size/page caps.

## 4.3 Website / AI-System Discovery — NOW

M5 identifies, on the labelled demo site:

- AI-powered features
- copilots
- public AI policies
- model/provider disclosures
- privacy/security documentation
- documentation links

This remains an **authorized discovery capability**, not generic internet scanning. Extracted items are candidates until a human approves them as evidence.

## 4.4 Document-to-Control Mapping — NOW

Use extracted requirements to suggest relevant controls.

Human approval remains mandatory for authoritative mappings.

---

# 5. Threat Intelligence

## 5.1 Threat Map — NOW

The idea discussed was a global heat map of attacks/security incidents.

**Do not build a generic news globe.**

M7 ships the useful version:

**Threat → Technique → AI System Risk → Control → Validation Test → Coverage**

Sources in the curated catalog:

- MITRE ATLAS (public locators)
- OWASP GenAI (public locators)
- labelled lab advisory for the order-support demo

The view answers:

> Which AI threats matter to us, which controls mitigate them, and have those controls actually been tested?

Not:

> What security news happened today?

## 5.2 Nordic Threat and Readiness Radar — NOW / PHASE 1

The workspace-scoped Radar ingests fixed official CISA KEV, NSM, FIRST EPSS, CERT-SE, NCSC-FI, ENISA EUVD, and CERT-EU sources. SAMSIK and CERT-IS use a bounded manual metadata/link boundary because no approved stable machine-readable contract was established.

Implemented capabilities:

- Explicit advisory, vulnerability, campaign, incident-report, and national-risk-level event types.
- Separate authority, target, victim, infrastructure, and prevalence geography without attacker-origin inference.
- Versioned deterministic exact-duplicate and cross-source related-event clusters.
- Explainable workspace relevance and bounded country, sector, vendor, product, technology, event, source, time, relevance, and exploitation filters.
- Timeline/list modes and workspace-owned saved views.
- Workspace-owned triage, owner, priority, due date, rationale, and audit history.
- Manual links to workspace business services and explicitly workspace-bound controls, evidence, and systems.

Source content remains untrusted informational data. It does **not** directly change control status, prove customer exposure, establish an incident, or create a legal-compliance result.

## 5.3 Threat-to-Control Coverage — NOW

Show techniques against current control coverage. Unmapped techniques are `EVIDENCE_REQUIRED`. Mapped coverage follows existing assurance statuses. Candidate tests point at AUTH-01 / AUTH-02 and do not auto-execute.

Example:

```text
Tool abuse / OWASP LLM08
        ↓
CTRL-002 Tool authorization
        ↓
AUTH-01 (candidate)
        ↓
GAP_DETECTED / VALIDATED / EVIDENCE_REQUIRED
```

---

# 6. Enterprise Dashboard & UX

## 6.1 New UI From Scratch — NOW

Do not copy the old ThreatSight 1.x UI.

The new interface should be intentionally designed around the assurance model and enterprise workflows.

Prioritize:

- clean visual hierarchy
- executive dashboard
- control health
- AI-system inventory
- findings
- evidence
- remediation
- retesting
- governance mappings
- traceability

## 6.2 Executive Assurance Dashboard — NOW

Show high-level posture such as:

- AI systems
- critical/high control gaps
- validated controls
- stale evidence
- assurance coverage
- open remediation
- recent regressions

Avoid noisy SOC-style alert walls.

The executive dashboard is a security-operations Overview: six questions, threat landscape evidence states, exposure by severity, tested vs untested assurance, an action queue, and recent activity. Default view is the labelled Nordic Retail showcase when those rows exist. Each metric still has a drill-down or provenance source. This is not live enterprise discovery and not a legal compliance result.

## 6.3 Control Detail View — NOW

A control page should show:

- requirement
- policy
- expected behavior
- tests
- latest verdict
- evidence
- failed traces
- remediation
- retest history
- framework mappings

## 6.4 Evidence Explorer — NOW

Allow an engineer/auditor to reconstruct exactly why a control received its status.

## 6.5 AI-System Detail — NOW

Show the complete assurance state of one agent/system.

## 6.6 Modern Enterprise Visual Design — NOW

The UI is part of the showcase value. It should feel like a serious enterprise security product rather than an admin CRUD application.

---

# 7. Deployment & Enterprise Architecture

## 7.1 Docker Deployment — NOW

The complete showcase product should run locally in Docker.

Target:

```text
Browser
   ↓
ThreatSight Web
   ↓
ThreatSight API
   ├── Governance engine
   ├── Control engine
   ├── Assurance engine
   ├── Evidence store
   └── Intelligence engine
        ↓
      Postgres
```

Exact services are an architectural decision to make during implementation, not inherited from 1.x.

## 7.2 In-House Deployment — NOW

Docker-first self-hosting. Lab stack via `make up`. Production-like overlay via `make up-enterprise`.

- no mandatory cloud dependency
- private model/API configuration
- controlled outbound access
- local evidence storage
- shared-token authentication (not SSO)
- auditor read-only role
- audit trail
- `make backup` / restore with `--yes`

## 7.3 Security Boundaries — NOW

The assurance engine must enforce:

- explicit target authorization
- scope
- expiry
- rate limits
- sandbox-by-default execution
- deterministic safety decisions
- kill switch
- evidence integrity

---

# 8. Integrations

## 8.1 GRC Export — NOW

Export assurance evidence as JSON/CSV and `threatsight.grc.v1` rather than replacing GRC platforms. `legal_compliance_claim` is always false. Not a live connector.

## 8.2 Saidot Integration — FOUNDATION

The GRC bundle can carry AI system inventory, controls, evidence, and assurance status. Treat Saidot-class platforms as complementary. No live Saidot API client.

## 8.3 CI/CD — NOW

GitHub Actions runs isolated tests and compose-config validation. Full `make test` is the self-hosted live gate. Do not use the assurance engine as a production attack job.

## 8.4 Observability / OTEL — FUTURE

Consume standardized agent traces where appropriate.

Do not make a specific telemetry vendor mandatory.

---

# 9. Reporting

## 9.1 Evidence-backed Assurance Report — NEXT

Generate reports suitable for:

- engineering review
- security review
- internal audit
- management
- customer/security questionnaires

## 9.2 Control Matrix — NOW

Export a matrix of:

```text
Control | Requirement | Test | Result | Evidence | Owner | Framework | Freshness
```

## 9.3 Executive Summary — NOW

Provide concise management-level conclusions with links to evidence.

AI-generated narrative must remain subordinate to deterministic underlying evidence.

---

# 10. Explicitly Out of Scope

These should not quietly return through feature creep:

- generic SaaS/GRC replacement
- legal compliance certification
- generic vulnerability scanner
- generic HTTP/network scanner
- jailbreak leaderboard
- runtime AI firewall
- autonomous production attack execution
- global security-news dashboard as the primary product
- replacing Promptfoo/Garak
- copying the ThreatSight 1.x UI
- importing the 1.x scanner architecture into the new product

---

# 11. Showcase / CV Features

The final portfolio build should demonstrate real enterprise engineering rather than just CRUD screens.

High-value showcase capabilities:

1. AI system inventory
2. Governance document ingestion
3. Requirement extraction with source citations
4. Human approval workflow
5. Control library
6. EU AI Act / GDPR / NIST / ISO informational mappings
7. Control-to-test traceability
8. Live agent control validation
9. Deterministic PASS/FAIL/INCONCLUSIVE
10. Evidence trace and cryptographic hash
11. Remediation recommendation
12. FAIL → remediation → PASS retest
13. Evidence freshness
14. Executive assurance dashboard
15. Engineer evidence explorer
16. Docker self-hosted deployment
17. Clean enterprise UI
18. Audit trail

These features together demonstrate **AI governance + AI security assurance**, rather than another generic SaaS application.

---

# 12. Product Principle

> **ThreatSight does not declare that an organization is compliant. It helps the organization turn requirements into controls and controls into testable, evidence-backed assurance.**

The product should always distinguish:

- requirement
- control
- test
- observation
- evidence
- verdict
- remediation
- legal/compliance interpretation

That separation is fundamental to the architecture.
