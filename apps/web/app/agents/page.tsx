"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import "./agents.css";

// Everything on this page comes from the separate demo-world service (/api/world/*):
// a fictional organisation (Nordvik Municipality or Helio Cloud), seeded in memory per run, never
// written to the ThreatSight database.

type Label = { synthetic: boolean; organisation: string; notice: string };
type Connection = { id: string; label: string; model: string; kind: "local" | "endpoint" };
type Profile = { id: string; name: string; organisation: string; kind: string; policy: string; currency: string; summary: string };
type Meta = Label & { models: string[]; live_model: string | null; policies: string[]; guardable?: string[]; connections?: Connection[]; profile?: Profile; profiles?: Profile[] };
type GraphTool = { name: string; impact: string; data: string; guarded: boolean };
type Agent = {
  id: string;
  agent: string;
  control: string;
  inputs: string[];
  tools: GraphTool[];
  data: string[];
  factors: { reach: number; impact: number; sensitivity: number; guardrails: number };
  score: number;
  worst_path: { input: string; tool: string; data: string };
};
type Graph = Label & { policy: string; agents: Agent[] };
type Replay = { model: string; tries: number; max_tries: number; hostile_attempt: boolean; recorded: string };
type Scenario = { id: string; title: string; agent: string; control: string; control_title: string; tags: string[]; agentic?: string[]; atlas?: string[]; attack_message: string; replay: Replay | null };

function modelLabel(m: string, meta: Meta, replay: Replay | null) {
  if (m === "live") return `Default AI model: ${meta.live_model} (set in Settings)`;
  if (m === "replay") return replay ? `Recorded run of ${replay.model}` : "Recorded run: none yet";
  const c = meta.connections?.find((x) => x.id === m);
  if (c) return c.kind === "local" ? `Local AI model: ${c.label}` : `Your agent: ${c.label}`;
  if (m !== "scripted") return m;
  return "Scripted (no AI model, same result every time)";
}
type ToolCall = { name: string; args: Record<string, unknown>; allowed: boolean; executed: boolean; rule: string | null; held?: boolean };
type Approval = {
  run: number;
  call: number;
  decision: "approve" | "reject";
  approver: string;
  decided: string;
  verdict: { verdict: string; reason_code: string; summary: string };
};
type Decide = (call: number, decision: "approve" | "reject", approver: string) => Promise<void>;
type TranscriptEvent = { type: string; content?: string; text?: string; name?: string; args?: unknown; result?: unknown; tool_calls?: { name: string; arguments: unknown }[] };
type Assessment = {
  model: string;
  policy: string;
  verdict: { verdict: string; reason_code: string; summary: string };
  tool_calls: ToolCall[];
  effects: Record<string, unknown>[];
  transcript: TranscriptEvent[];
};
type Run = Label & {
  id: string;
  created: string;
  scenario: string;
  title: string;
  agent: string;
  control: string;
  mode: string;
  verdict: string;
  runs: Assessment[];
  utility?: { task: string; passed: boolean | null }[];
  evidence: { records: number; head: string; signed: boolean; valid: boolean; message: string };
  approvals?: Approval[];
};
type RunRow = { id: string; created: string; scenario: string; agent: string; mode: string; verdict: string; verdicts: string[]; model: string; policy: string; profile?: string };

async function getJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...init });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `${response.status} ${response.statusText}`);
  }
  return body as T;
}

const POLICY_LABEL: Record<string, string> = { open: "No guardrails", "nordvik-hardened": "With policy", "helio-hardened": "With policy" };

const VERDICT_LABEL: Record<string, string> = { FAIL: "Harm done", PASS: "Stopped", INCONCLUSIVE: "No attack tried" };

function policyLabel(policy: string) {
  return policy.startsWith("custom") ? "Your guardrails" : POLICY_LABEL[policy] ?? policy;
}

function verdictLabel(verdict: string | undefined) {
  return VERDICT_LABEL[verdict ?? ""] ?? verdict ?? "";
}

function tone(verdict: string | undefined) {
  if (verdict === "FAIL") return "proven";
  if (verdict === "PASS") return "fixed";
  return "exposed";
}

function scoreTone(score: number) {
  return score >= 60 ? "proven" : score >= 35 ? "exposed" : "fixed";
}

function shortHash(hash: string) {
  return `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

type Toggle = (tool: string) => void;

function Map({ agent, guardable, onToggle }: { agent: Agent; guardable: string[]; onToggle: Toggle }) {
  const W = 760;
  const rowH = 46;
  const rows = Math.max(agent.inputs.length, agent.tools.length, agent.data.length, 1);
  const H = rows * rowH + 40;
  const col = [70, 270, 470, 670];
  const y = (i: number, n: number) => 20 + (H - 40) / 2 + (i - (n - 1) / 2) * rowH;
  const agentY = H / 2;
  const worst = agent.worst_path;
  return (
    <svg className="ws-map" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Capability map for ${agent.agent}`}>
      <defs>
        <pattern id="ws-grid" width="24" height="24" patternUnits="userSpaceOnUse">
          <path d="M24 0H0V24" fill="none" className="ws-gridline" />
        </pattern>
      </defs>
      <rect width={W} height={H} fill="url(#ws-grid)" />
      {["Untrusted input", "Agent", "Tools", "Data reached"].map((label, i) => (
        <text key={label} x={col[i]} y={14} className="ws-colhead" textAnchor="middle">
          {label.toUpperCase()}
        </text>
      ))}
      {agent.inputs.map((input, i) => {
        const hot = input === worst.input;
        return (
          <path key={`e-in-${input}`} d={`M${col[0] + 62} ${y(i, agent.inputs.length)} C ${col[0] + 120} ${y(i, agent.inputs.length)}, ${col[1] - 100} ${agentY}, ${col[1] - 62} ${agentY}`} className={`ws-edge${hot ? " ws-edge-hot" : ""}`} />
        );
      })}
      {agent.tools.map((tool, i) => {
        const ty = y(i, agent.tools.length);
        const di = agent.data.indexOf(tool.data);
        const dy = y(di, agent.data.length);
        const hot = tool.name === worst.tool;
        const state = tool.guarded ? "ws-edge-guarded" : hot ? "ws-edge-hot" : "";
        return (
          <g key={`e-tool-${tool.name}`}>
            <path d={`M${col[1] + 62} ${agentY} C ${col[1] + 120} ${agentY}, ${col[2] - 100} ${ty}, ${col[2] - 66} ${ty}`} className={`ws-edge ${state}`} />
            <path d={`M${col[2] + 66} ${ty} C ${col[2] + 120} ${ty}, ${col[3] - 100} ${dy}, ${col[3] - 62} ${dy}`} className={`ws-edge ${state}`} />
          </g>
        );
      })}
      {agent.inputs.map((input, i) => (
        <g key={`n-in-${input}`} transform={`translate(${col[0]} ${y(i, agent.inputs.length)})`}>
          <rect x={-62} y={-15} width={124} height={30} rx={4} className="ws-node ws-node-input" />
          <text className="ws-nodetext" textAnchor="middle" dy="4">{input}</text>
        </g>
      ))}
      <g transform={`translate(${col[1]} ${agentY})`}>
        <rect x={-62} y={-22} width={124} height={44} rx={6} className={`ws-node ws-node-agent ws-${scoreTone(agent.score)}`} />
        <text className="ws-nodetext ws-strong" textAnchor="middle" dy="-2">{agent.agent}</text>
        <text className="ws-nodetext ws-small" textAnchor="middle" dy="13">score {agent.score}</text>
      </g>
      {agent.tools.map((tool, i) => {
        const clickable = guardable.includes(tool.name);
        const hint = clickable
          ? tool.guarded
            ? `${tool.name} is guarded. Click to remove the guard.`
            : `Click to guard ${tool.name}`
          : `${tool.name} only reads data; it needs no guard`;
        return (
        <g
          key={`n-tool-${tool.name}`}
          transform={`translate(${col[2]} ${y(i, agent.tools.length)})`}
          className={clickable ? "ws-clickable" : undefined}
          role={clickable ? "button" : undefined}
          tabIndex={clickable ? 0 : undefined}
          aria-pressed={clickable ? tool.guarded : undefined}
          aria-label={hint}
          onClick={clickable ? () => onToggle(tool.name) : undefined}
          onKeyDown={clickable ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onToggle(tool.name); } } : undefined}
        >
          <title>{hint}</title>
          <rect x={-66} y={-15} width={132} height={30} rx={4} className={`ws-node ws-node-tool ws-impact-${tool.impact}${tool.guarded ? " ws-guarded" : ""}`} />
          <text className="ws-nodetext ws-mono" textAnchor="middle" dy="4">{tool.name}</text>
          {tool.guarded ? <text className="ws-lock" x={56} y={-6} textAnchor="middle">◆</text> : null}
        </g>
        );
      })}
      {agent.data.map((d, i) => (
        <g key={`n-data-${d}`} transform={`translate(${col[3]} ${y(i, agent.data.length)})`}>
          <rect x={-62} y={-15} width={124} height={30} rx={15} className={`ws-node ws-node-data${d === worst.data ? " ws-hot" : ""}`} />
          <text className="ws-nodetext" textAnchor="middle" dy="4">{d}</text>
        </g>
      ))}
    </svg>
  );
}

function TranscriptLine({ event }: { event: TranscriptEvent }) {
  if (event.type === "input") {
    return (
      <li className="ws-line ws-line-input">
        <span className="ws-tag">Message in</span>
        <span>{event.content ?? event.text}</span>
      </li>
    );
  }
  if (event.type === "assistant") {
    const said = event.content || event.text;
    return (
      <li className="ws-line ws-line-agent">
        <span className="ws-tag">Agent replied</span>
        <span>{said || <em className="ws-muted">(no reply, it only acted)</em>}</span>
      </li>
    );
  }
  return null;
}

function HeldCall({ index, approval, onDecide }: { index: number; approval?: Approval; onDecide: Decide }) {
  const [approver, setApprover] = useState("Ingrid Dahl, finance (demo)");
  const [busy, setBusy] = useState(false);
  if (approval) {
    return (
      <div className={`ws-approval ws-border-${tone(approval.verdict.verdict)}`}>
        <span className={`ws-${approval.decision === "approve" ? "exposed" : "fixed"}`}>
          {approval.decision === "approve" ? "APPROVED" : "REJECTED"} by {approval.approver}
        </span>
        <span title={approval.verdict.reason_code}>{approval.verdict.summary}</span>
      </div>
    );
  }
  const go = async (decision: "approve" | "reject") => {
    setBusy(true);
    try {
      await onDecide(index, decision, approver);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="ws-approval ws-border-exposed">
      <span className="ws-exposed">Paused: a named person must approve or reject this</span>
      <label className="ws-model">
        Approver
        <input value={approver} maxLength={80} onChange={(e) => setApprover(e.target.value)} />
      </label>
      <button type="button" className="ws-btn ws-btn-small" disabled={busy || !approver.trim()} onClick={() => go("reject")}>
        Reject
      </button>
      <button type="button" className="ws-btn ws-btn-small" disabled={busy || !approver.trim()} onClick={() => go("approve")}>
        Approve
      </button>
    </div>
  );
}

function callState(call: ToolCall) {
  if (call.executed) return "Done";
  if (call.held) return "Paused for approval";
  return "Blocked by policy";
}

function AssessmentView({ a, label, approvals, onDecide }: { a: Assessment; label: string; approvals: Approval[]; onDecide: Decide }) {
  return (
    <section className={`ws-assess ws-border-${tone(a.verdict.verdict)}`}>
      <header className="ws-assess-head">
        <span className="ws-eyebrow">{label}</span>
        <span className="ws-muted">{policyLabel(a.policy)}</span>
        <span className={`ws-verdict ws-${tone(a.verdict.verdict)}`} title={a.verdict.verdict}>{verdictLabel(a.verdict.verdict)}</span>
      </header>
      <p className="ws-summary" title={a.verdict.reason_code}>{a.verdict.summary}</p>
      <ol className="ws-transcript">
        {a.transcript.map((event, i) => (
          <TranscriptLine key={i} event={event} />
        ))}
      </ol>
      <h4 className="ws-subhead">What the agent actually did</h4>
      <ul className="ws-calls">
        {a.tool_calls.length === 0 ? <li className="ws-muted">It took no action.</li> : null}
        {a.tool_calls.map((call, i) => (
          <li key={i} className={call.executed ? "ws-call-ran" : call.held ? "ws-call-held" : "ws-call-blocked"}>
            <div className="ws-call-row">
              <code>
                {call.name}({Object.entries(call.args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ")})
              </code>
              <span className="ws-callstate" title={call.rule ?? undefined}>{callState(call)}</span>
            </div>
            {call.held ? <HeldCall index={i} approval={approvals.find((x) => x.call === i)} onDecide={onDecide} /> : null}
          </li>
        ))}
      </ul>
    </section>
  );
}

function initialProfile(): string {
  if (typeof window === "undefined") return "nordvik";
  const fromUrl = new URLSearchParams(window.location.search).get("profile");
  if (fromUrl) return fromUrl;
  try {
    return window.localStorage.getItem("ts-profile") ?? "nordvik";
  } catch {
    return "nordvik";
  }
}

export default function AgentsPage() {
  const [profile, setProfile] = useState("nordvik");
  const [meta, setMeta] = useState<Meta | null>(null);
  const [graphs, setGraphs] = useState<Record<string, Graph>>({});
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [policy, setPolicy] = useState("open");
  const [guard, setGuard] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [model, setModel] = useState("scripted");
  const [run, setRun] = useState<Run | null>(null);
  const [history, setHistory] = useState<RunRow[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [verify, setVerify] = useState<{ valid: boolean; message: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshHistory = useCallback(() => {
    getJson<{ runs: RunRow[] }>("/api/world/runs")
      .then((b) => setHistory(b.runs))
      .catch(() => undefined);
  }, []);

  useEffect(() => setProfile(initialProfile()), []);

  useEffect(() => {
    let cancelled = false;
    setGraphs({});
    setPolicy("open");
    setGuard([]);
    setRun(null);
    setVerify(null);
    getJson<Meta>(`/api/world/meta?profile=${profile}`)
      .then((m) => {
        const hard = m.profile?.policy ?? "nordvik-hardened";
        return Promise.all([
          getJson<Graph>(`/api/world/graph?profile=${profile}&policy=open`),
          getJson<Graph>(`/api/world/graph?profile=${profile}&policy=${hard}`),
          getJson<{ scenarios: Scenario[] }>(`/api/world/scenarios?profile=${profile}`),
        ]).then(([open, hardGraph, sc]) => {
          if (cancelled) return;
          setMeta(m);
          setGraphs({ open, [hard]: hardGraph });
          setScenarios(sc.scenarios);
          setSelected(open.agents[0]?.id ?? null);
          setModel((cur) => (m.models.includes(cur) && cur !== "scripted" ? cur : m.models.includes("live") ? "live" : m.models.includes("replay") ? "replay" : "scripted"));
        });
      })
      .catch((e: Error) => setError(`Demo world service is not reachable: ${e.message}`));
    refreshHistory();
    return () => {
      cancelled = true;
    };
  }, [profile, refreshHistory]);

  function chooseProfile(p: string) {
    setProfile(p);
    try {
      window.localStorage.setItem("ts-profile", p);
    } catch {
      /* private window: the choice just isn't remembered */
    }
    const url = new URL(window.location.href);
    url.searchParams.set("profile", p);
    window.history.replaceState(null, "", url.toString());
  }

  const guardable = useMemo(() => meta?.guardable ?? [], [meta]);
  const hard = meta?.profile?.policy ?? "nordvik-hardened";
  const graphKey = policy === "custom" ? `custom:${guard.join(",")}` : policy;
  // Keep showing the last map while the graph for a new tool choice loads.
  const lastGraph = useRef<Graph | undefined>(undefined);
  const graph = graphs[graphKey] ?? lastGraph.current;
  lastGraph.current = graph;

  useEffect(() => {
    if (policy !== "custom" || graphs[graphKey]) return;
    getJson<Graph>(`/api/world/graph?profile=${profile}&policy=custom&guard=${encodeURIComponent(guard.join(","))}`)
      .then((g) => setGraphs((prev) => ({ ...prev, [graphKey]: g })))
      .catch((e: Error) => setError(e.message));
  }, [policy, guard, graphKey, graphs, profile]);

  function choosePolicy(p: string) {
    setPolicy(p);
    setGuard(p === hard ? guardable : []);
  }

  // Clicking a tool on the map adds or removes just that tool's rules from the organisation's policy.
  function toggleTool(tool: string) {
    const current = policy === "custom" ? guard : policy === hard ? guardable : [];
    const next = (current.includes(tool) ? current.filter((t) => t !== tool) : [...current, tool]).sort();
    if (next.length === 0) return choosePolicy("open");
    if (next.length === guardable.length) return choosePolicy(hard);
    setGuard(next);
    setPolicy("custom");
  }
  const agent = graph?.agents.find((a) => a.id === selected) ?? null;
  const scenario = scenarios.find((s) => s.id === selected) ?? null;
  const shown = history.filter((r) => (r.profile ?? "nordvik") === profile);
  const openScore = useMemo(() => Object.fromEntries((graphs.open?.agents ?? []).map((a) => [a.id, a.score])), [graphs]);

  async function start(mode: "run" | "retest") {
    if (!selected) return;
    setBusy(mode);
    setError(null);
    setVerify(null);
    try {
      const result = await getJson<Run>("/api/world/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          policy === "custom"
            ? { scenario: selected, mode, policy, guard, model }
            : { scenario: selected, mode, policy: mode === "run" ? policy : "open", model },
        ),
      });
      setRun(result);
      refreshHistory();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function open(id: string) {
    setVerify(null);
    try {
      const r = await getJson<Run>(`/api/world/runs/${id}`);
      setRun(r);
      setSelected(r.scenario);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function decide(runIndex: number, call: number, decision: "approve" | "reject", approver: string) {
    if (!run) return;
    setError(null);
    setVerify(null);
    try {
      const r = await getJson<Run>(`/api/world/runs/${run.id}/approvals`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ run: runIndex, call, decision, approver }),
      });
      setRun(r);
      refreshHistory();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function check() {
    if (!run) return;
    try {
      setVerify(await getJson<{ valid: boolean; message: string }>(`/api/world/runs/${run.id}/verify`));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="ws">
      <div className="ws-banner" role="note">
        <span className="ws-banner-tag">Demo</span>
        <span>{meta?.profile?.name ?? "Nordvik Municipality"} is fictional. No real people, systems or payments are involved.</span>
      </div>

      <div className="ws-profile" role="group" aria-label="Organisation">
        <span className="ws-muted">Organisation</span>
        {(meta?.profiles ?? []).map((p) => (
          <button key={p.id} type="button" aria-pressed={profile === p.id} onClick={() => chooseProfile(p.id)} title={p.summary}>
            {p.name} <span className="ws-muted">· {p.kind}</span>
          </button>
        ))}
      </div>

      <header className="ws-head">
        <div>
                    <h1 className="ws-title">What can your AI agents actually do?</h1>
          <ol className="ws-steps">
            <li><strong>Pick an agent.</strong> The risk score shows how much harm it could do with the tools it has.</li>
            <li><strong>Run the attack.</strong> See what the agent really does, not what it says.</li>
            <li><strong>Fix and retest.</strong> Turn on the policy and prove the harm is now stopped.</li>
          </ol>
          <p className="ws-muted ws-small">
            Want ThreatSight to propose the fix? <a href={`/agents/fixes?profile=${profile}`}>Guardrail fixes</a> picks one rule, proves it against the attack and waits for your approval.
          </p>
        </div>
        <div className="ws-switch" role="group" aria-label="Policy">
          {(meta?.policies ?? ["open", hard]).map((p) => (
            <button key={p} type="button" aria-pressed={policy === p} onClick={() => choosePolicy(p)}>
              {POLICY_LABEL[p] ?? p}
            </button>
          ))}
          {policy === "custom" ? (
            <button type="button" aria-pressed="true">
              Your choice
            </button>
          ) : null}
        </div>
      </header>

      {error ? <p className="ws-error">{error}</p> : null}
      {!graph && !error ? <p className="ws-muted">Loading the demo world…</p> : null}

      {graph ? (
        <div className="ws-grid">
          <nav className="ws-agents" aria-label="Agents">
            {graph.agents.map((a) => {
              const before = openScore[a.id];
              return (
                <button key={a.id} type="button" className={`ws-agent${a.id === selected ? " is-active" : ""}`} onClick={() => setSelected(a.id)}>
                  <span className="ws-agent-name">{a.agent}</span>
                  <span className="ws-agent-control">Risk score</span>
                  <span className={`ws-score ws-${scoreTone(a.score)}`}>{a.score}</span>
                  <span className="ws-bar">
                    <span className={`ws-bar-fill ws-bg-${scoreTone(a.score)}`} style={{ width: `${a.score}%` }} />
                  </span>
                  {before !== undefined && before !== a.score ? <span className="ws-delta">was {before}</span> : null}
                </button>
              );
            })}
          </nav>

          {agent ? (
            <section className="ws-panel">
              <Map agent={agent} guardable={guardable} onToggle={toggleTool} />
              <dl className="ws-factors">
                <div><dt>Harm it can do</dt><dd>{agent.factors.impact}</dd></div>
                <div><dt>Data sensitivity</dt><dd>{agent.factors.sensitivity}</dd></div>
                <div><dt>What it can reach</dt><dd>{agent.factors.reach}</dd></div>
                <div><dt>Guardrails on</dt><dd>{agent.factors.guardrails}%</dd></div>
              </dl>
              <p className="ws-path">
                Worst case: <strong>{agent.worst_path.input}</strong> → <code>{agent.worst_path.tool}</code> → <strong>{agent.worst_path.data}</strong>
              </p>
              <p className="ws-legend">
                <span className="ws-key ws-key-hot" /> dangerous and unguarded <span className="ws-key ws-key-guarded" /> guarded by the policy <span className="ws-tip">Click a tool to guard it, then press Fix and retest.</span>
              </p>
            </section>
          ) : null}
        </div>
      ) : null}

      {scenario ? (
        <section className="ws-panel ws-console">
          <header className="ws-console-head">
            <div>
              <p className="ws-eyebrow" title={[scenario.control, ...scenario.tags, ...(scenario.agentic ?? []), ...(scenario.atlas ?? [])].join(" · ")}>Try the attack</p>
              <h2 className="ws-h2">{scenario.title}</h2>
              <p className="ws-attack"><span className="ws-tag">Attack message</span> {scenario.attack_message}</p>
            </div>
            <div className="ws-actions">
              {meta && meta.models.length > 1 ? (
                <label className="ws-model">
                  Agent brain
                  <select value={model} onChange={(e) => setModel(e.target.value)}>
                    {meta.models.map((m) => (
                      <option key={m} value={m} disabled={m === "replay" && !scenario.replay}>
                        {modelLabel(m, meta, scenario.replay)}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                null
              )}
              {model === "replay" && scenario.replay ? (
                <span className="ws-muted ws-small" title={`Recorded ${scenario.replay.recorded}`}>
                  {scenario.replay.hostile_attempt
                    ? `Attack landed on try ${scenario.replay.tries} of ${scenario.replay.max_tries}`
                    : `No attack attempt in ${scenario.replay.max_tries} tries`}
                </span>
              ) : null}
              <button type="button" className="ws-btn" disabled={busy !== null || (model === "replay" && !scenario.replay)} onClick={() => start("run")}>
                {busy === "run" ? "Running…" : "Run attack"}
              </button>
              <button type="button" className="ws-btn ws-btn-primary" disabled={busy !== null || (model === "replay" && !scenario.replay)} onClick={() => start("retest")}>
                {busy === "retest" ? "Retesting…" : "Fix and retest"}
              </button>
            </div>
          </header>

          {run && run.scenario === scenario.id ? (
            <>
              <div className={`ws-assessments ws-cols-${run.runs.length}`}>
                {run.runs.map((a, i) => (
                  <AssessmentView
                    key={i}
                    a={a}
                    label={run.runs.length > 1 ? (i === 0 ? "Before the fix" : "After the fix") : "Result"}
                    approvals={(run.approvals ?? []).filter((x) => x.run === i)}
                    onDecide={(call, decision, approver) => decide(i, call, decision, approver)}
                  />
                ))}
              </div>
              {run.utility ? (
                <div className="ws-utility">
                  <span className="ws-eyebrow">Normal work still runs</span>
                  {run.utility.map((u) => (
                    <span key={u.task} className={`ws-chip ws-${u.passed ? "fixed" : u.passed === false ? "proven" : "exposed"}`}>
                      {u.passed ? "✓" : u.passed === false ? "✗" : "?"} {u.task}
                    </span>
                  ))}
                </div>
              ) : null}
              <footer className="ws-evidence">
                <span className="ws-eyebrow">Tamper-proof record</span>
                <span className="ws-muted" title={`head ${shortHash(run.evidence.head)}, ${run.evidence.signed ? "HMAC signed" : "hash chained, unsigned"}`}>{run.evidence.records} entries, each linked to the one before</span>
                <button type="button" className="ws-btn ws-btn-small" onClick={check}>Check the record</button>
                <a className="ws-btn ws-btn-small ws-btn-primary" href={`/agents/report/${run.id}`} target="_blank" rel="noopener">
                  Open the one-page report
                </a>
                <a className="ws-btn ws-btn-small" href={`/api/world/runs/${run.id}/inspect.json`} download title="An evaluation log for Inspect AI's log viewer (inspect view)">
                  Download Inspect AI log
                </a>
                {verify ? <span className={`ws-chip ws-${verify.valid ? "fixed" : "proven"}`}>{verify.valid ? "✓ " : "✗ Changed: "}{verify.message}</span> : null}
              </footer>
            </>
          ) : (
            <p className="ws-muted">Press Run attack to see what the agent says next to what it actually does.</p>
          )}
        </section>
      ) : null}

      {shown.length > 0 ? (
        <section className="ws-panel">
          <p className="ws-eyebrow">Earlier runs</p>
          <table className="ws-table">
            <thead>
              <tr><th>When (UTC)</th><th>Agent</th><th>Run</th><th>Result</th><th>Report</th></tr>
            </thead>
            <tbody>
              {shown.slice(0, 10).map((r) => (
                <tr key={r.id} onClick={() => open(r.id)} className={run?.id === r.id ? "is-active" : undefined}>
                  <td className="ws-mono">{r.created.replace("T", " ").replace("Z", "")}</td>
                  <td>{r.agent}</td>
                  <td>{r.mode === "retest" ? "Fix and retest" : policyLabel(r.policy)}</td>
                  <td>
                    {(r.verdicts ?? [r.verdict]).map((v, i) => (
                      <span key={i}>
                        {i > 0 ? <span className="ws-muted"> → </span> : null}
                        <span className={`ws-${tone(v)}`}>{verdictLabel(v)}</span>
                      </span>
                    ))}
                  </td>
                  <td>
                    <a href={`/agents/report/${r.id}`} target="_blank" rel="noopener" onClick={(e) => e.stopPropagation()}>
                      Report
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}
    </div>
  );
}
