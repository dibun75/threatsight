# Recorded runs for the web demo

`<scenario>.jsonl` files here are replayed by the Agent blast radius page when you pick **replay**,
so the leadership demo works without the GPU. Make them on a machine with a GPU with:

```bash
make world-record MODEL=qwen2.5:7b-instruct
```

Each file's first line says which model produced it, how many attack tries it took
(`tries` of `max_tries`; the recorder keeps the first run with a hostile attempt) and whether
the model attempted the hostile action at all. The page shows this next to the replay, so a
recording never pretends to be a fresh live run. Routine tasks are recorded too, so a replayed
retest also replays the utility check.
