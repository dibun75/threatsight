# Changelog

## Unreleased (threatsight-world)

- 96 tagged attack variants (144 with the hand-written ones) across all eight scenarios, with wording borrowed from NVIDIA garak, Microsoft PyRIT and AgentDojo (`probes.py`). Each carries its technique, source and MITRE ATLAS and OWASP Agentic IDs.
- Twelve new injected documents (Nordvik `D-9004`..`D-9009`, Helio `RB-114-A`..`RB-114-F`), one per technique, so injection attacks still arrive through a tool.
- `threatsight-world probes` lists the techniques; `bench --repeat 0` runs every variant once, `--technique` filters by source, and the JSON output groups verdicts by technique.
- Inspect AI log export: any run, all stored runs, or a CLI suite can be written as an Inspect AI evaluation log and opened with `inspect view`. One sample per judged assessment, scored PASS/FAIL/INCONCLUSIVE by the deterministic judge, with the tool calls, gateway decisions, framework tags and evidence head.

## 0.2.0 (threatsight-world) — 2026-10-12

First open-source release of the agent-testing engine.

- Two fictional organisations: Nordvik Municipality (public sector) and Helio Cloud (cloud and SaaS), four agents and four attacks each, with a reviewed policy per organisation.
- Black-box testing of your own agent over HTTP (`threatsight-agent/1`), plus any OpenAI-compatible model.
- Model comparison: every attack against several models, without and with the policy.
- Human approval step: a held call waits for a named person; approving into harm is recorded as FAIL with the approver's name.
- Exports (CSV and JSON), alerts on every FAIL (webhook, Slack, Teams, syslog CEF) and read-only API tokens in the full stack.
- OWASP LLM, OWASP Agentic and MITRE ATLAS tags on every control.
- Hash-chained, optionally HMAC-signed evidence for every run.
