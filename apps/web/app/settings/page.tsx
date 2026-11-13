"use client";

import { useCallback, useEffect, useState } from "react";

import "../agents/agents.css";
import "../compare/compare.css";
import "./settings.css";

import { csrfHeaders } from "@/lib/api";
import { ModelEndpoints, postJson, worldJson, type Connection } from "@/components/ModelEndpoints";

// Settings an administrator can change without editing .env and restarting:
// - AI models for the agents and guardrail fixes, kept by the demo-world service (/api/world/settings);
// - the AI provider for documents and intelligence, and a few platform limits, kept by the API (/api/v1/settings).
// Keys are write-only on both sides. Everything else in the environment is shown read-only.

type WorldSettings = {
  local: { base_url: string; model: string | null; has_key: boolean; key_source: "saved" | "environment" | null };
  agent: string | null;
  proposer: string | null;
  saved: string[];
  defaults: { local_base: string; local_model: string | null; has_key: boolean; proposer: string | null };
  connections: Connection[];
  effective: { agent: string | null; proposer: string | null };
  labels: { agent: string | null; proposer: string | null };
};
type Probe = { reachable: boolean; models: string[]; error: string | null };
type Item = {
  key: string; label: string; kind: "choice" | "text" | "url" | "secret" | "int" | "bool"; help: string; group: "ai" | "platform";
  choices: string[]; minimum: number | null; maximum: number | null; source: "saved" | "environment"; env_var: string;
  updated_by: string | null; updated_at: string | null; value?: string | number | boolean; env_value?: string | number | boolean;
  is_set?: boolean; env_is_set?: boolean;
};
type ApiSettings = { editable: Item[]; fixed: { key: string; label: string; value: unknown; env_var: string }[] };

async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...init, headers: { "Content-Type": "application/json", ...csrfHeaders(), ...(init?.headers ?? {}) } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : `${response.status} ${response.statusText}`);
  return body as T;
}

const ADMIN = new Set(["platform-admin", "workspace-admin", "admin"]);

export default function SettingsPage() {
  const [role, setRole] = useState<string | null>(null);
  useEffect(() => {
    apiJson<{ role: string }>("/api/v1/auth/session").then((me) => setRole(me.role || "")).catch(() => setRole(""));
  }, []);

  return (
    <div className="ws settings">
      <header className="ws-head">
        <div>
          <h1 className="ws-title">Settings</h1>
          <p className="ws-muted">
            Changes here take effect straight away and override the matching value in <code>.env</code>. Clearing one goes back to the
            <code>.env</code> value. API keys are kept on the server and never shown again.
          </p>
        </div>
      </header>
      {role === null ? <p className="ws-muted">Loading…</p> : !ADMIN.has(role) ? (
        <p className="ws-error" role="alert">Only an administrator can open Settings.</p>
      ) : (
        <>
          <AgentModels />
          <ApiSection group="ai" title="AI for documents and threat intelligence"
            intro="Used to pull requirements out of uploaded documents and to summarise threat intelligence. The built-in heuristics need no model." />
          <ApiSection group="platform" title="Platform" intro="Limits and the emergency stop." />
          <Fixed />
        </>
      )}
    </div>
  );
}

function Source({ saved, env }: { saved: boolean; env: string }) {
  return <span className="set-source">{saved ? "Saved here" : <>From <code>{env}</code></>}</span>;
}

function AgentModels() {
  const [view, setView] = useState<WorldSettings | null>(null);
  const [base, setBase] = useState("");
  const [model, setModel] = useState("");
  const [key, setKey] = useState("");
  const [probe, setProbe] = useState<Probe | "busy" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const v = await worldJson<WorldSettings>("/api/world/settings");
    setView(v);
    setBase(v.local.base_url);
    setModel(v.local.model ?? "");
  }, []);

  useEffect(() => {
    load().catch((e) => setError((e as Error).message));
  }, [load]);

  async function save(body: Record<string, unknown>, done: string) {
    setError(null);
    setNotice(null);
    try {
      const v = await worldJson<WorldSettings>("/api/world/settings", postJson(body));
      setView(v);
      setBase(v.local.base_url);
      setModel(v.local.model ?? "");
      setKey("");
      setNotice(done);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function test() {
    setProbe("busy");
    try {
      setProbe(await worldJson<Probe>("/api/world/settings/probe", postJson({ local_base: base, local_key: key || undefined })));
    } catch (e) {
      setProbe({ reachable: false, models: [], error: (e as Error).message });
    }
  }

  if (!view) {
    return <section className="ws-panel"><h2 className="ws-h2">AI models for agents and guardrail fixes</h2>{error ? <p className="ws-error">{error}</p> : <p className="ws-muted">Loading…</p>}</section>;
  }

  const savedLocal = view.saved.some((k) => k.startsWith("local_"));
  const found = probe && probe !== "busy" ? probe.models : [];
  const options = view.connections;

  return (
    <section className="ws-panel" aria-labelledby="models-title">
      <h2 className="ws-h2" id="models-title">AI models for agents and guardrail fixes</h2>
      {error ? <p className="ws-error" role="alert">{error}</p> : null}
      {notice ? <p className="set-ok" role="status">{notice}</p> : null}

      <h3 className="set-h3">Which model does what</h3>
      <div className="cmp-form">
        <label>
          Agents run on
          <select value={view.agent ?? ""} onChange={(e) => save({ agent: e.target.value }, "Agent model saved.")}>
            <option value="">{view.local.model ? `Default local model (${view.local.model})` : "Scripted only (no model set up)"}</option>
            {options.map((o) => <option key={o.id} value={o.id}>{o.label}{o.kind === "local" ? " · local" : " · endpoint"}</option>)}
          </select>
        </label>
        <label>
          Guardrail fixes are proposed by
          <select value={view.proposer ?? ""} onChange={(e) => save({ proposer: e.target.value }, "Fix proposer saved.")}>
            <option value="">Same as the agents{view.labels.agent && !view.proposer ? ` (${view.labels.agent})` : ""}</option>
            {options.map((o) => <option key={o.id} value={o.id}>{o.label}{o.kind === "local" ? " · local" : " · endpoint"}</option>)}
          </select>
        </label>
      </div>
      <p className="ws-muted">
        Now: agents use <strong>{view.labels.agent ?? "the scripted baseline"}</strong>, fixes are proposed by <strong>{view.labels.proposer ?? "the built-in rules"}</strong>.
        The built-in rules (no model) can always be picked on the Guardrail fixes page.
      </p>

      <h3 className="set-h3">Local model server (Ollama, vLLM, LM Studio)</h3>
      <p className="ws-muted">
        The address is resolved from the world service, not your browser. Inside Docker, <code>localhost</code> is the container itself:
        use <code>http://host.docker.internal:11434/v1</code> on Docker Desktop, or the Docker bridge (often <code>http://172.17.0.1:11434/v1</code>) on Linux.
      </p>
      <form className="cmp-form" onSubmit={(e) => { e.preventDefault(); save({ local_base: base, local_model: model, ...(key ? { local_key: key } : {}) }, "Local model server saved."); }}>
        <label>Base URL <Source saved={view.saved.includes("local_base")} env="THREATSIGHT_LLM_BASE_URL" />
          <input required maxLength={300} value={base} onChange={(e) => setBase(e.target.value)} placeholder="http://172.17.0.1:11434/v1" />
        </label>
        <label>Default model <Source saved={view.saved.includes("local_model")} env="THREATSIGHT_LLM_MODEL" />
          <input list="local-models" maxLength={120} value={model} onChange={(e) => setModel(e.target.value)} placeholder="qwen2.5:7b-instruct" />
          <datalist id="local-models">{found.map((m) => <option key={m} value={m} />)}</datalist>
        </label>
        <label>API key (optional){view.local.has_key ? ` · ${view.local.key_source === "saved" ? "saved" : "set in .env"}` : ""}
          <input type="password" autoComplete="off" maxLength={500} value={key} onChange={(e) => setKey(e.target.value)} placeholder={view.local.has_key ? "Leave empty to keep it" : ""} />
        </label>
        <div className="set-actions">
          <button type="button" className="ws-btn" onClick={test} disabled={probe === "busy" || !base}>{probe === "busy" ? "Testing…" : "Test connection"}</button>
          <button type="submit" className="ws-btn ws-btn-primary">Save</button>
        </div>
      </form>
      {probe && probe !== "busy" ? (
        probe.reachable ? (
          <p className={probe.error ? "cmp-warn" : "cmp-good"} role="status">
            {probe.error ?? `Reached it. ${probe.models.length} chat model${probe.models.length === 1 ? "" : "s"}: ${probe.models.join(", ")}.`}
            {!probe.error && model && !probe.models.includes(model) ? ` ${model} is not among them; pull it first.` : ""}
          </p>
        ) : <p className="cmp-bad" role="alert">{probe.error}</p>
      ) : null}
      {savedLocal || view.local.key_source === "saved" ? (
        <p className="ws-muted">
          <button type="button" className="ws-btn ws-btn-small" onClick={() => save({ local_base: "", local_model: "", clear_local_key: true }, "Back to the .env values.")}>Use the .env values</button>{" "}
          .env has <code>{view.defaults.local_base}</code>{view.defaults.local_model ? <> with <code>{view.defaults.local_model}</code></> : ", no model"}.
        </p>
      ) : null}

      <h3 className="set-h3">Hosted models and your own agents</h3>
      <p className="ws-muted">OpenRouter, OpenAI, another Ollama server, or your agent&apos;s endpoint. Each one can then run the agents, propose fixes, or be compared.</p>
      <ModelEndpoints onChange={() => load().catch(() => undefined)} />
    </section>
  );
}

function display(v: unknown): string {
  if (v === true) return "on";
  if (v === false) return "off";
  if (v === null || v === undefined || v === "") return "not set";
  return String(v);
}

function ApiSection({ group, title, intro }: { group: "ai" | "platform"; title: string; intro: string }) {
  const [items, setItems] = useState<Item[] | null>(null);
  const [draft, setDraft] = useState<Record<string, string | boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [probe, setProbe] = useState<Probe | "busy" | null>(null);

  const fill = useCallback((list: Item[]) => {
    const mine = list.filter((i) => i.group === group);
    setItems(mine);
    setDraft(Object.fromEntries(mine.filter((i) => i.kind !== "secret").map((i) => [i.key, i.kind === "bool" ? Boolean(i.value) : i.key === "max_document_bytes" ? String(Number(i.value) / 1048576) : String(i.value ?? "")])));
  }, [group]);

  useEffect(() => {
    apiJson<ApiSettings>("/api/v1/settings").then((v) => fill(v.editable)).catch((e) => setError((e as Error).message));
  }, [fill]);

  function toValue(item: Item, raw: string | boolean): unknown {
    if (item.kind === "bool") return Boolean(raw);
    if (item.key === "max_document_bytes") return Math.round(Number(raw) * 1048576);
    if (item.kind === "int") return Number(raw);
    return raw;
  }

  async function send(values: Record<string, unknown>, done: string) {
    setError(null);
    setNotice(null);
    try {
      const v = await apiJson<ApiSettings & { changed: string[] }>("/api/v1/settings", { method: "PATCH", body: JSON.stringify({ values }) });
      fill(v.editable);
      setNotice(v.changed.length ? done : "Nothing changed.");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  function save(e: React.FormEvent) {
    e.preventDefault();
    if (!items) return;
    const values: Record<string, unknown> = {};
    for (const item of items) {
      const raw = draft[item.key];
      if (item.kind === "secret") {
        if (typeof raw === "string" && raw.trim()) values[item.key] = raw.trim();
        continue;
      }
      const next = toValue(item, raw ?? "");
      if (next !== item.value) values[item.key] = next;
    }
    send(values, "Saved.");
  }

  async function test() {
    setProbe("busy");
    try {
      const key = draft.openai_api_key;
      setProbe(await apiJson<Probe>("/api/v1/settings/ai/test", { method: "POST", body: JSON.stringify({ base_url: draft.openai_base_url, api_key: typeof key === "string" && key ? key : undefined }) }));
    } catch (e) {
      setProbe({ reachable: false, models: [], error: (e as Error).message });
    }
  }

  return (
    <section className="ws-panel" aria-label={title}>
      <h2 className="ws-h2">{title}</h2>
      <p className="ws-muted">{intro}</p>
      {error ? <p className="ws-error" role="alert">{error}</p> : null}
      {notice ? <p className="set-ok" role="status">{notice}</p> : null}
      {items === null ? (error ? null : <p className="ws-muted">Loading…</p>) : (
        <form className="set-grid" onSubmit={save}>
          {group === "ai" ? (
            <div className="ws-profile" role="group" aria-label="Provider presets">
              <span className="ws-muted">Fill in</span>
              {[["OpenAI", "https://api.openai.com/v1", "gpt-4o-mini"], ["OpenRouter", "https://openrouter.ai/api/v1", "openai/gpt-4o-mini"], ["Ollama", "http://172.17.0.1:11434/v1", "qwen2.5:7b-instruct"]].map(([name, url, m]) => (
                <button key={name} type="button" onClick={() => setDraft({ ...draft, openai_base_url: url, openai_model: m })}>{name}</button>
              ))}
            </div>
          ) : null}
          {items.map((item) => {
            const id = `set-${item.key}`;
            const raw = draft[item.key];
            return (
              <div key={item.key} className="set-row">
                <label htmlFor={id}>{item.label} <Source saved={item.source === "saved"} env={item.env_var} /></label>
                {item.kind === "choice" ? (
                  <select id={id} value={String(raw ?? "")} onChange={(e) => setDraft({ ...draft, [item.key]: e.target.value })}>
                    {item.choices.map((c) => <option key={c} value={c}>{c === "heuristic" ? "Built-in heuristics (no model)" : c === "openai" ? "AI model (endpoint below)" : c}</option>)}
                  </select>
                ) : item.kind === "bool" ? (
                  <input id={id} type="checkbox" checked={Boolean(raw)} onChange={(e) => setDraft({ ...draft, [item.key]: e.target.checked })} />
                ) : item.kind === "secret" ? (
                  <input id={id} type="password" autoComplete="off" maxLength={500} value={String(raw ?? "")} placeholder={item.is_set ? "Set. Leave empty to keep it" : "Not set"}
                    onChange={(e) => setDraft({ ...draft, [item.key]: e.target.value })} />
                ) : item.key === "max_document_bytes" ? (
                  <input id={id} type="number" min={1} max={50} step={1} value={String(raw ?? "")} onChange={(e) => setDraft({ ...draft, [item.key]: e.target.value })} aria-describedby={`${id}-help`} />
                ) : (
                  <input id={id} type={item.kind === "int" ? "number" : "text"} min={item.minimum ?? undefined} max={item.maximum ?? undefined} maxLength={item.kind === "url" ? 300 : 120}
                    value={String(raw ?? "")} onChange={(e) => setDraft({ ...draft, [item.key]: e.target.value })} />
                )}
                <p className="ws-muted set-help" id={`${id}-help`}>
                  {item.key === "max_document_bytes" ? "In MB, from 1 to 50." : item.help}
                  {item.source === "saved" ? (
                    <>
                      {" "}Saved by {item.updated_by}{item.updated_at ? ` on ${item.updated_at.slice(0, 16).replace("T", " ")}` : ""}. .env has {item.kind === "secret" ? (item.env_is_set ? "a key" : "no key") : display(item.env_value)}.{" "}
                      <button type="button" className="ws-btn ws-btn-small" onClick={() => send({ [item.key]: null }, `${item.label} is back to the .env value.`)}>Use .env</button>
                    </>
                  ) : null}
                </p>
              </div>
            );
          })}
          <div className="set-actions">
            {group === "ai" ? <button type="button" className="ws-btn" onClick={test} disabled={probe === "busy"}>{probe === "busy" ? "Testing…" : "Test connection"}</button> : null}
            <button type="submit" className="ws-btn ws-btn-primary">Save</button>
          </div>
          {group === "ai" && probe && probe !== "busy" ? (
            probe.reachable
              ? <p className="cmp-good" role="status">Reached it. {probe.models.length} model{probe.models.length === 1 ? "" : "s"} listed{probe.models.length ? `, including ${probe.models.slice(0, 5).join(", ")}` : ""}.</p>
              : <p className="cmp-bad" role="alert">{probe.error}</p>
          ) : null}
        </form>
      )}
    </section>
  );
}

function Fixed() {
  const [rows, setRows] = useState<ApiSettings["fixed"] | null>(null);
  useEffect(() => {
    apiJson<ApiSettings>("/api/v1/settings").then((v) => setRows(v.fixed)).catch(() => setRows([]));
  }, []);
  if (!rows?.length) return null;
  return (
    <section className="ws-panel" aria-labelledby="fixed-title">
      <h2 className="ws-h2" id="fixed-title">Set when ThreatSight is deployed</h2>
      <p className="ws-muted">
        These decide how the platform starts and who can sign in, so they stay in <code>.env</code> (or your orchestrator&apos;s secrets) and need a restart.
        Database credentials, sign-in secrets and threat feed keys are not shown.
      </p>
      <table className="ws-table">
        <thead><tr><th>Setting</th><th>Value</th><th>Variable</th></tr></thead>
        <tbody>
          {rows.map((r) => <tr key={r.key}><td>{r.label}</td><td>{display(r.value)}</td><td><code>{r.env_var}</code></td></tr>)}
        </tbody>
      </table>
    </section>
  );
}
