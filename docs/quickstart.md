# Quickstart

## Two minutes, just Python

You need Python 3.12 or newer. The engine has no other dependencies.

```bash
git clone https://github.com/dibun75/threatsight && cd threatsight
pip install ./apps/world
threatsight-world list                                  # the eight scenarios
threatsight-world suite --profile all --policy open     # no guardrails: every attack does harm, exit 1
threatsight-world suite --profile all                   # each organisation's policy: every attack stopped, exit 0
```

One scenario, start to finish, with a tamper-evident record:

```bash
threatsight-world retest payment-injection --evidence ev.jsonl   # before FAIL, after PASS, normal work checked
threatsight-world verify ev.jsonl                                # check the hash chain
```

Exit codes: `0` PASS, `1` FAIL, `2` INCONCLUSIVE, `3` model endpoint unreachable.

These runs use the built-in scripted agent, a fixture that obeys the hostile text while saying it refuses. To test a real model, see [Test your own agent](test-your-agent.md).

## The full app with Docker

```bash
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.quickstart.yml up -d --build
```

Then open:

- `http://localhost:3000/agents`: each agent's blast radius, run an attack, fix and retest.
- `http://localhost:3000/agents/fixes`: propose a guardrail fix, see it proven, apply and roll back.
- `http://localhost:3000/compare`: compare models or your own agent on the same attacks.

Sign-in is off and everything listens on `127.0.0.1` only. Stop it with `docker compose -f docker-compose.yml -f docker-compose.quickstart.yml down`.

On a machine that already runs other Docker projects, `make up` picks free host ports and starts only this project; `make ports` shows what it chose.

## Use a local model

Install [Ollama](https://ollama.com), pull a tool-calling model and point the CLI at it:

```bash
ollama pull qwen3:4b
threatsight-world run payment-injection --policy open --model openai \
  --base-url http://localhost:11434/v1 --model-name qwen3:4b
```

In the web app, set the model server on the **Settings** page. From inside Docker, `localhost` is the container itself: use `http://host.docker.internal:11434/v1` on Docker Desktop, or the Docker bridge address (by default `http://172.17.0.1:11434/v1`) on Linux.
