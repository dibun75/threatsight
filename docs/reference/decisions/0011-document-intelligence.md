# ADR 0011 — Document intelligence candidates are not authoritative

**Status:** Accepted  
**Date:** 2026-08-27

## Context

M2 must ingest PDF, DOCX, and text, extract requirement/control/evidence/AI-system candidates, and preserve provenance. An LLM or heuristic extractor is useful for proposing text. It is not allowed to create governance records, approve mappings, or declare legal compliance.

Uploaded documents are untrusted. Prompt-injection text inside a policy must never become a system instruction, tool call, or network action.

## Decision

- Persist original file metadata, SHA-256 content hash, extracted text, and locators (page/section/quote).
- Uploading changed bytes creates a new `document_versions` row. Identical hashes on the same document are rejected.
- Extraction is provider-agnostic. The domain schema does not name a commercial model. The default provider is a deterministic heuristic so tests and air-gapped deploys need no API keys.
- Extracted items are `pending` candidates. Only an explicit human review (`approved`, `rejected`, `needs_revision`) can change that.
- Only approved candidates materialize M1 governance records (requirement, control, evidence). AI-system references are informational and do not auto-create inventory.
- Mapping an approved requirement to a control records reviewer identity and document provenance. The mapping remains informational.
- Extraction output is schema-validated. Unknown fields (including tool calls and review/assurance status) are dropped. `COMPLIANT` is rejected.
- Document content never authorizes tools, network access, code execution, or a legal-compliance label.

## Consequences

- Reviewers can trace a requirement to document version, hash, and page/section quote.
- History is preserved across versions; earlier candidates remain.
- Enabling an optional remote provider later must still pass the same schema and human-approval gate.
