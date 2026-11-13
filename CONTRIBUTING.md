# Contributing to ThreatSight

Thanks for helping. ThreatSight tests what AI agents actually do with their tools, and proves it with tamper-evident evidence. Contributions that keep that promise honest are very welcome.

## Ground rules

- **Fictional data only.** Scenarios run against made-up organisations (Nordvik Municipality, Helio Cloud). Never add real people, companies, accounts, or customer data, and never point a scenario at a real system.
- **Verdicts are deterministic.** A judge reads tool attempts and recorded effects, never what the model said. An LLM is never the final authority on PASS or FAIL.
- **Fail closed.** A policy rule that errors denies the call. New rule types must be reviewed JSON, not code that a request can inject.
- **Demo data stays out of the real database.** The demo world has no database connection on purpose.

## Getting set up

```bash
# Engine only (standard library, no services needed)
pip install -e "./apps/world[dev]"
pytest apps/world/tests -q
threatsight-world suite --profile all

# Full stack (API, web, Postgres, demo world)
cp .env.example .env
make up          # picks free ports, starts only the threatsight project
make smoke
```

API tests that need Postgres are skipped unless `THREATSIGHT_TEST_USE_LIVE_DB=1` and `THREATSIGHT_DATABASE_URL` are set.

## Adding a scenario

1. Add the fictional data to the profile's world (`world.py` for Nordvik, `helio.py` for Helio Cloud).
2. Add the tool, if a new one is needed, to `tools.py`. Tools are naive on purpose: safety must come from the gateway.
3. Write the `Scenario`: system prompt, tools, the hostile message, a scripted attack, a `ControlSpec` (what counts as a hostile attempt, what counts as harm), OWASP and MITRE ATLAS tags, and at least one routine task that must still work under the policy.
4. Add a rule to the profile's policy in `policies/` so the hardened run passes.
5. Add six phrasings to `variants.py`, the scenario's frame to `probes.py` (or, for an injection that arrives through a tool, its documents to `injections.py`), and the graph inputs to `graph.py`.
6. Run `pytest apps/world/tests -q` and `threatsight-world suite --profile all`.

## Pull requests

- Keep changes focused, with tests. CI must be green.
- Describe what a reader would see before and after.
- By contributing you agree that your contribution is licensed under the Apache License 2.0.
