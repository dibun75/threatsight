# Framework assurance

M6 maps controls to curated framework items. It is not a legal-compliance engine.

## Catalog

Items exist for:

- EU AI Act
- GDPR
- NIST AI RMF
- ISO/IEC 42001
- OWASP GenAI / LLM Top 10
- MITRE ATLAS

Each item stores a public locator, an informational statement, a source kind, and `catalog_version`. The catalog is incomplete. ISO entries are index pointers; statute text is not reproduced.

## Coverage

Coverage is derived from mapped controls' assurance statuses:

- no mapped controls → `EVIDENCE_REQUIRED`
- any `GAP_DETECTED` → `GAP_DETECTED`
- otherwise the documented evidence-based vocabulary

Never `COMPLIANT`. An LLM is not the coverage authority.

## Mapping

`POST /api/v1/controls/{id}/framework-mappings` remains the write path. M6 bootstrap can attach CTRL-002 to a suggested informational set. Duplicate maps return 409.
