# Limits

ThreatSight is honest about what a run proves. Read this before quoting a result.

- **The world is fictional.** Agents run against seeded, in-memory organisations. A PASS shows that your agent and policy stopped these attacks on these tools, not that your production system is safe.
- **The scripted agent is a fixture.** The default `--model scripted` exists for CI and demos. It says nothing about any real model. Results that matter come from `--model openai` or your own agent.
- **INCONCLUSIVE is common with real models.** If a model never attempts the hostile action, the control was not tested. Run the variants (`bench --repeat 0`) and several models before drawing conclusions.
- **Model results depend on the setup.** Model version, quantisation, temperature, prompt and hardware all change the outcome. The numbers in the README come from one machine on one date.
- **Eight scenarios, not full coverage.** They cover payment fraud, cross-user data access, permission changes, privilege escalation and indirect prompt injection. Many agent risks are not modelled.
- **Policies are simple JSON rules**, not OPA or Cedar, and cover what the scenarios need.
- **Framework tags are the author's mapping.** The OWASP and MITRE ATLAS tags help you find related guidance. Check them before relying on them.
- **No compliance verdicts.** ThreatSight never declares legal or regulatory compliance. An LLM is never the final authority on a verdict.
- **Verified fixes stay in the fictional world.** Remediation writes new policy versions for the demo world only. It does not write to live connectors or change real systems.
- **The wider platform** (connectors, threat intelligence, exposure graph) is fixture-tested unless a document says otherwise. See [reference/](reference/) for each part's maturity.
