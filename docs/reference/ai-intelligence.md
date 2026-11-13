# AI intelligence layer

**Status:** M15 — provider-agnostic intelligence behind a service boundary. Showcase copy must not imply LLM authorship when the heuristic path ran.

ThreatSight may use an LLM to interpret, classify, correlate, recommend, and summarize. It must never authorize security actions or override deterministic PASS/FAIL.

## Boundary

```text
Untrusted input (documents, traces, catalog text)
        ↓
Intelligence provider (heuristic default, optional OpenAI)
        ↓  schema-validated JSON
Intelligence run (provider, model, prompt version, confidence, uncertainty)
        ↓
Human review for consequential governance changes
```

The extraction path from M2 is unchanged. M13 adds sibling tasks:

| Task | Purpose |
| --- | --- |
| `classify_system` | Summarize purpose, data, users, capabilities. Missing fields stay UNKNOWN. |
| `suggest_mappings` | Informational requirement/control suggestions. |
| `correlate_threats` | Informational threat → technique → capability → control links. |
| `missing_governance` | List recorded gaps. Does not invent facts. |
| `explain_posture` | Evidence-linked explanation with source IDs. |

## Trust rules

- API keys come from `THREATSIGHT_OPENAI_API_KEY`. They are never persisted.
- LLM output is untrusted. Extra fields are dropped. `COMPLIANT` is rejected.
- Prompt-injection text cannot issue application commands.
- Deterministic policy remains the verdict authority.
- External model calls are rate-limited (20/minute). If the LLM is unavailable, the heuristic provider is used.
- `GET /api/v1/intelligence/explain` is heuristic and does not persist. Operators may `POST` to persist an audit row.

## What this is not

- A legal-compliance engine.
- Model-dependent authorization.
- An autonomous attack planner.
