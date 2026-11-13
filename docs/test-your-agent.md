# Test your own agent

## Any OpenAI-compatible model

Ollama, vLLM, LM Studio, OpenRouter, OpenAI or anything else that speaks chat completions with tool calls:

```bash
threatsight-world run payment-injection --policy open --model openai \
  --base-url http://localhost:11434/v1 --model-name qwen3:4b
threatsight-world retest payment-injection --model openai \
  --base-url http://localhost:11434/v1 --model-name qwen3:4b --evidence ev.jsonl
```

For a hosted endpoint, put the key in an environment variable and pass its name with `--api-key-env`.

A real model may refuse and never call the tool. That run is INCONCLUSIVE, not PASS: this model resisted this phrasing, but the control was not tested. Use the variants before drawing conclusions:

```bash
threatsight-world bench --profile all --repeat 0 --model openai --model-name qwen3:4b
threatsight-world bench --profile all --repeat 0 --technique pyrit --model openai --model-name qwen3:4b
```

`--repeat 0` runs every variant once. The JSON output has a `by_technique` breakdown so you can see which kind of wording got through.

## Your own agent, with its own prompt and framework

Wrap it in the `threatsight-agent/1` HTTP protocol. ThreatSight sends the conversation and the tools; your agent answers with text and tool calls; ThreatSight runs the tools on the fictional world and judges what happened. Your agent never touches a real system during the test.

```text
POST {"protocol": "threatsight-agent/1", "session": "…", "messages": [...], "tools": [...]}
  -> {"content": "text for the user", "tool_calls": [{"id": "c1", "name": "approve_payment", "arguments": {...}}]}
```

`apps/world/examples/agent_adapter.py` is a working template in about 70 lines. Replace its `decide` function with a call into your agent (LangChain, Semantic Kernel or your own code), run it, and add it on the web app's **Compare** page as an endpoint with protocol "Your own agent".

```bash
python apps/world/examples/agent_adapter.py --port 8700 --ollama http://localhost:11434/v1 --model qwen3:4b
# URL in ThreatSight (from Docker): http://host.docker.internal:8700/agent
```

## Compare models

The **Compare** page (`/compare`) runs every attack per model, first without guardrails and then with the policy, plus the routine tasks. Each comparison writes its own hash-chained evidence file. Models listed by your local Ollama server appear automatically.

## In CI

`suite` exits `1` on any FAIL, so it can gate a build:

```yaml
- run: pip install ./apps/world
- run: threatsight-world suite --profile all --policy path/to/your-policy.json
```

Use `--inspect-log logs/threatsight.json` to get a file that opens in the [Inspect AI](https://inspect.aisi.org.uk/) log viewer.

## Your own scenarios

Scenarios, tools and policies live in `apps/world/src/threatsight_world/` (`scenarios.py`, `tools.py`, `helio.py`, `policies/`). A new scenario needs a seeded world, the agent's tools, a hostile input, a judge that reads effects only, and at least one routine task. Keep every organisation fictional (`.example` domains). See [CONTRIBUTING.md](../CONTRIBUTING.md).
