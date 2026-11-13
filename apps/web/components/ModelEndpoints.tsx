"use client";

import { useCallback, useEffect, useState } from "react";

// Model and agent endpoints the demo-world service can run attacks against (/api/world/connections).
// Only an administrator reaches these routes (middleware.ts). Keys are write-only: the service
// stores them in connections.json (mode 0600) and only ever answers whether one is saved.

export type Connection = { id: string; label: string; model: string; kind: "local" | "endpoint"; base_url?: string; has_key?: boolean; protocol?: "openai" | "agent" };
type Check = { reachable: boolean; tool_calling: boolean; error: string | null; ms: number };

export async function worldJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...init });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || body.detail || `${response.status} ${response.statusText}`);
  return body as T;
}

export const postJson = (body: unknown): RequestInit => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

const PRESETS: { id: string; name: string; label: string; base_url: string; model: string; needsKey: boolean; note: string }[] = [
  { id: "openrouter", name: "OpenRouter", label: "OpenRouter", base_url: "https://openrouter.ai/api/v1", model: "qwen/qwen-2.5-72b-instruct", needsKey: true,
    note: "Use a model that supports tool calls. Your OpenRouter key is stored on the server." },
  { id: "openai", name: "OpenAI", label: "OpenAI", base_url: "https://api.openai.com/v1", model: "gpt-4o-mini", needsKey: true, note: "Needs an OpenAI API key." },
  { id: "ollama", name: "Ollama on another machine", label: "Ollama", base_url: "http://10.0.0.5:11434/v1", model: "qwen2.5:7b-instruct", needsKey: false,
    note: "Replace the address with the machine running Ollama. Use the local model server above for the default one." },
  { id: "custom", name: "Other", label: "", base_url: "", model: "", needsKey: false, note: "Anything that speaks the OpenAI chat format with tool calls (vLLM, LM Studio, Azure OpenAI), or your own agent." },
];

export function ModelEndpoints({ onChange }: { onChange?: () => void }) {
  const [items, setItems] = useState<Connection[]>([]);
  const empty = { label: "", base_url: "", model: "", api_key: "", protocol: "openai" as "openai" | "agent" };
  const [form, setForm] = useState(empty);
  const [preset, setPreset] = useState("custom");
  const [checks, setChecks] = useState<Record<string, Check | "busy">>({});
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const data = await worldJson<{ connections: Connection[] }>("/api/world/connections");
    setItems(data.connections.filter((c) => c.kind === "endpoint"));
  }, []);

  useEffect(() => {
    load().catch((e) => setError((e as Error).message));
  }, [load]);

  function choose(id: string) {
    setPreset(id);
    const p = PRESETS.find((x) => x.id === id);
    if (p) setForm({ ...empty, label: p.label, base_url: p.base_url, model: p.model });
  }

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await worldJson("/api/world/connections", postJson(form));
      setForm(empty);
      setPreset("custom");
      await load();
      onChange?.();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function check(id: string) {
    setChecks((c) => ({ ...c, [id]: "busy" }));
    try {
      const r = await worldJson<Check>(`/api/world/connections/${id}/check`, postJson({}));
      setChecks((c) => ({ ...c, [id]: r }));
    } catch (err) {
      setChecks((c) => ({ ...c, [id]: { reachable: false, tool_calling: false, error: (err as Error).message, ms: 0 } }));
    }
  }

  async function remove(id: string) {
    try {
      await worldJson(`/api/world/connections/${id}`, { method: "DELETE" });
      await load();
      onChange?.();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const active = PRESETS.find((p) => p.id === preset);

  return (
    <div className="cmp-endpoints">
      {error ? <p className="ws-error" role="alert">{error}</p> : null}
      {items.length ? (
        <table className="ws-table">
          <thead>
            <tr><th>Name</th><th>Address</th><th>Model</th><th>Connection</th><th /></tr>
          </thead>
          <tbody>
            {items.map((c) => {
              const r = checks[c.id];
              return (
                <tr key={c.id}>
                  <td>{c.label}</td>
                  <td><code>{c.base_url}</code>{c.has_key ? " · key saved" : ""}</td>
                  <td>{c.protocol === "agent" ? "Your own agent" : <code>{c.model}</code>}</td>
                  <td>
                    {r === "busy" ? "Checking…" : r ? (
                      r.reachable ? (
                        <span className={r.tool_calling ? "cmp-good" : "cmp-warn"}>{r.tool_calling ? `Works, calls tools (${(r.ms / 1000).toFixed(1)}s)` : r.error}</span>
                      ) : <span className="cmp-bad">Not reachable: {r.error}</span>
                    ) : (
                      <button type="button" className="ws-btn ws-btn-small" onClick={() => check(c.id)}>Test</button>
                    )}
                  </td>
                  <td><button type="button" className="ws-btn ws-btn-small" onClick={() => remove(c.id)}>Remove</button></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : <p className="ws-muted">No endpoints added yet.</p>}

      <div className="ws-profile" role="group" aria-label="Provider">
        <span className="ws-muted">Add</span>
        {PRESETS.map((p) => (
          <button key={p.id} type="button" aria-pressed={preset === p.id} onClick={() => choose(p.id)}>{p.name}</button>
        ))}
      </div>
      {active ? <p className="ws-muted">{active.note}</p> : null}

      <form className="cmp-form" onSubmit={add}>
        <label>Name<input required maxLength={80} value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="Finance agent v2" /></label>
        {preset === "custom" ? (
          <label>
            Speaks
            <select value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value as "openai" | "agent" })}>
              <option value="openai">OpenAI chat format</option>
              <option value="agent">Your own agent (threatsight-agent/1)</option>
            </select>
          </label>
        ) : null}
        <label>
          {form.protocol === "agent" ? "Agent URL" : "Base URL"}
          <input required maxLength={300} value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })}
            placeholder={form.protocol === "agent" ? "http://10.0.0.5:8700/agent" : "http://10.0.0.5:11434/v1"} />
        </label>
        {form.protocol === "openai" ? (
          <label>Model<input required maxLength={120} value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} placeholder="llama3.1:8b" /></label>
        ) : null}
        <label>API key{active?.needsKey ? "" : " (optional)"}
          <input type="password" autoComplete="off" required={active?.needsKey} maxLength={500} value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })} />
        </label>
        <button type="submit" className="ws-btn">Add endpoint</button>
      </form>
      <p className="ws-muted">
        A hosted service receives the fictional attack messages. For your own agent, ThreatSight sends each turn as <code>threatsight-agent/1</code> JSON;
        a ready-made wrapper is in <code>apps/world/examples/agent_adapter.py</code>. Keys are stored on the server and never shown again.
      </p>
    </div>
  );
}
