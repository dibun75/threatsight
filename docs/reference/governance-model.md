# Governance Model

Governance in ThreatSight 2 is the path from organizational requirements to controls. It is not a legal-compliance engine.

## Objects (M1)

1. **AI system** — named asset under assurance (owner, environment, lifecycle).
2. **Requirement** — titled statement with source type/reference, version, and review status. M2 may create an approved requirement from a human-approved document candidate; M1 still supports manual entry.
3. **Control** — versionable assurance object. See [control-model.md](./control-model.md).
4. **Requirement ↔ control mapping** — many-to-many, with optional rationale and provenance. A mapping does not establish compliance.
5. **Evidence record** — manual observation/document pointer. File ingestion is later.
6. **Framework reference** — catalog entry (EU AI Act, GDPR, NIST AI RMF, ISO/IEC 42001, OWASP GenAI, MITRE ATLAS) with public locator and informational statement. Informational only. Catalog is incomplete.
7. **Review** — reviewer, decision, comment, timestamp on requirement/control/mapping/evidence.
8. **Audit event** — append-only mutation log.

## Human review

No LLM-generated requirement becomes an authoritative control automatically. A reviewer can approve, reject, defer, or request changes. Approving a requirement updates its status; it still does not create a legal conclusion.

## Traceability question

> Why does this test exist, what requirement does it support, and what evidence proves the current state?

```text
Regulatory / Policy Requirement
            ↓
         Control
            ↓
          Test          (M3)
            ↓
         Evidence
            ↓
        Verdict         (M3)
            ↓
       Remediation
            ↓
         Retest
```

M1 answers the registry and mapping part of that question. M2 adds document-sourced candidates with human approval. M3 executes CTRL-002 tests and records technical verdicts; those verdicts are not legal conclusions. M6 adds curated framework items and coverage derived from mapped control statuses. M7 maps techniques to those controls and suggests candidate tests without executing them.
