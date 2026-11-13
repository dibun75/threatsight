# AI-system connectivity

**Status:** M13 — passive event/trace contract.

ThreatSight can ingest agent observations without assuming a single framework and without becoming a runtime firewall.

## Contract

`POST /api/v1/connectivity/events` accepts:

| Field | Meaning |
| --- | --- |
| `ai_system_id` | Existing inventory row. Required. |
| `source_kind` | `http_assessment`, `gateway`, `sdk`, or `otel` |
| `agent_id` / `session_id` / `user_context` | Identity context |
| `tool_name` / `arguments` | Observed tool call (arguments capped) |
| `authorization_context` | Observed authorization metadata |
| `result_metadata` | Observed result. Enforcement is recorded as `none`. |
| `occurred_at` / `correlation_id` | Timing and join key |
| `labelled_synthetic` | Required for demo traces |

Ingest is passive. It does not block, rewrite, or authorize tools. CTRL-002 verdicts still require a confirmed sandboxed assessment.

## Demo seed

Showcase bootstrap records a labelled synthetic gateway observation of unauthorized `cancel_order` on **Order support demo**. That row is not a FAIL verdict.

## What this is not

- A production runtime firewall.
- OpenTelemetry collection as a product.
- Arbitrary internet crawling or live SIEM ingest.
