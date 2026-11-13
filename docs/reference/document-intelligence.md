# Document Intelligence

M2 ingests organizational documents and produces **reviewable candidates**. It is not an autonomous compliance engine.

```text
Document → Provenance → Extracted candidates → Human approval → Governance records
```

## Supported inputs

- PDF
- DOCX
- plain text / Markdown

Maximum size is `THREATSIGHT_MAX_DOCUMENT_BYTES` (default 10 MiB). Encrypted PDFs, binaries, and unsupported types are rejected.

## Provenance

Every version stores:

- original filename and media kind
- SHA-256 of the file bytes
- extracted text and location map (page for PDFs; section for DOCX/Markdown)
- extraction timestamp, provider, and model

Every candidate stores a locator (page/section/offsets/quote) plus the parent document version hash. Authoritative requirements created from an approval keep `source_type=document` and a source reference that includes document id, version, page, and hash.

## Extraction

The extraction provider is configurable (`THREATSIGHT_EXTRACTION_PROVIDER`). The domain layer does not hard-code a commercial model.

| Provider | When used |
| --- | --- |
| `heuristic` (default) | Deterministic `shall`/`must`/Control:/Evidence: rules. No API key. |
| `openai` | Optional remote JSON extraction. Requires `THREATSIGHT_OPENAI_API_KEY`. Output is schema-validated. |

Providers return candidates only. They cannot set review status, assurance status, or legal-compliance labels.

## Review

Candidate states: `pending`, `approved`, `rejected`, `needs_revision`.

Only `approved` materializes an M1 record:

- requirement candidate → approved requirement
- control candidate → draft control with `HUMAN_REVIEW_REQUIRED`
- evidence statement → submitted document evidence
- AI-system reference → remains a reviewed candidate (no silent inventory create)

## Mapping

An approved requirement candidate can be:

- linked to an existing control
- used to propose a new control
- rejected as a mapping

Reviewer identity and document provenance are stored on the mapping.

## Security

- Documents are untrusted input.
- Instruction-like text (prompt injection, tool calls, `rm -rf`, “ignore previous instructions”) is not treated as a system command.
- Extraction cannot approve itself or label anything `COMPLIANT`.
- Document content cannot authorize tools, network access, or code execution.

## Not in M2

RAG/MCP, URL fetching, and threat intelligence. Hashed *run* envelopes belong to the M3 assurance engine, not to document ingest.
