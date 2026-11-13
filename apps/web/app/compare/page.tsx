"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import "../agents/agents.css";
import "./compare.css";

// Runs every attack of one fictional organisation (Nordvik or Helio Cloud) against each chosen model, without and with the policy, in the
// separate demo-world service (/api/world/*). Data is fictional and never stored in the ThreatSight database.

type Option = { id: string; label: string };
type Verdict = { verdict: string; reason_code: string; summary: string; calls: string[]; said: string };
type Cell = { before?: Verdict; after?: Verdict; utility?: { passed: number; total: number }; error?: string; ms: number };
type Summary = { model: string; label: string; harm_before: number; harm_after: number; work_passed: number; work_total: number; errors: number; scenarios: number };
type Job = {
  id: string;
  created: string;
  status: "queued" | "running" | "done" | "failed" | "interrupted";
  models: Option[];
  profile?: string;
  organisation?: string;
  scenarios: { id: string; agent: string; title: string; control: string }[];
  cells: Record<string, Cell>;
  done: number;
  total: number;
  summary?: Summary[];
  error?: string;
  evidence?: { records: number; valid: boolean; head: string };
};
type JobRow = { id: string; created: string; status: string; models: Option[]; done: number; total: number; profile?: string };
type Profile = { id: string; name: string; kind: string; summary: string };

async function getJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...init });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || body.detail || `${response.status} ${response.statusText}`);
  return body as T;
}

const post = (body: unknown): RequestInit => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

function outcome(v: Verdict | undefined): { text: string; tone: string } {
  if (!v) return { text: "–", tone: "muted" };
  if (v.verdict === "FAIL") return { text: "Harm done", tone: "bad" };
  if (v.verdict === "PASS") return { text: v.reason_code === "HELD_FOR_APPROVAL" ? "Paused for a person" : "Stopped", tone: "good" };
  if (v.reason_code === "NO_ATTEMPT") return { text: "Didn't take the bait", tone: "good" };
  return { text: "Tried, no harm", tone: "warn" };
}

const STATUS: Record<string, string> = { queued: "Waiting to start", running: "Running", done: "Finished", failed: "Stopped with an error", interrupted: "Interrupted by a restart" };

export default function ComparePage() {
  const [options, setOptions] = useState<Option[]>([]);
  const [chosen, setChosen] = useState<string[]>([]);
  const [jobs, setJobs] = useState<JobRow[]>([]);
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [owner, setOwner] = useState(false);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profile, setProfile] = useState("nordvik");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = useCallback(async () => {
    const data = await getJson<{ comparisons: JobRow[]; models: Option[] }>("/api/world/compare");
    setOptions(data.models);
    setJobs(data.comparisons);
    setChosen((prev) => (prev.length ? prev.filter((id) => data.models.some((m) => m.id === id)) : data.models.filter((m) => m.id !== "scripted").map((m) => m.id).slice(0, 3)));
  }, []);

  const follow = useCallback(async (id: string) => {
    if (timer.current) clearTimeout(timer.current);
    try {
      const j = await getJson<Job>(`/api/world/compare/${id}`);
      setJob(j);
      if (j.status === "queued" || j.status === "running") {
        timer.current = setTimeout(() => follow(id), 2000);
      } else {
        load().catch(() => undefined);
      }
    } catch (e) {
      setError((e as Error).message);
    }
  }, [load]);

  useEffect(() => {
    load().catch((e) => setError((e as Error).message));
    getJson<{ profiles: Profile[] }>("/api/world/profiles")
      .then((b) => setProfiles(b.profiles))
      .catch(() => undefined);
    try {
      const saved = new URLSearchParams(window.location.search).get("profile") ?? window.localStorage.getItem("ts-profile");
      if (saved) setProfile(saved);
    } catch {
      /* private window */
    }
    getJson<{ role: string }>("/api/v1/auth/session")
      .then((me) => setOwner(me.role === "platform-admin" || me.role === "workspace-admin" || me.role === "admin"))
      .catch(() => setOwner(false));
    const id = new URLSearchParams(window.location.search).get("id");
    if (id) follow(id);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [load, follow]);

  async function start() {
    setError(null);
    try {
      const j = await getJson<Job>("/api/world/compare", post({ models: chosen, profile }));
      window.history.replaceState(null, "", `/compare?id=${j.id}`);
      setJob(j);
      follow(j.id);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const running = job?.status === "queued" || job?.status === "running";
  const onlyScripted = options.length > 0 && options.every((o) => o.id === "scripted");

  return (
    <div className="ws">
      <div className="ws-banner" role="note">
        <span className="ws-banner-tag">Demo</span>
        <span>{job?.organisation?.replace(" (fictional)", "") ?? profiles.find((p) => p.id === profile)?.name ?? "Nordvik Municipality"} is fictional. The models only ever act on its made-up systems.</span>
      </div>

      <header className="ws-head">
        <div>
          <h1 className="ws-title">Which AI model can you trust with tools?</h1>
          <ol className="ws-steps">
            <li><strong>Pick the models,</strong> or your own agent&apos;s endpoint.</li>
            <li><strong>Run the comparison.</strong> Each one gets all four attacks, first with no guardrails, then with the policy.</li>
            <li><strong>Read the table.</strong> Judged only on what each model actually did, never on what it said.</li>
          </ol>
        </div>
      </header>

      {error ? <p className="ws-error">{error}</p> : null}

      <section className="ws-panel cmp-pick">
        <h2 className="ws-h2">Models to compare</h2>
        {profiles.length > 1 ? (
          <div className="ws-profile" role="group" aria-label="Organisation">
            <span className="ws-muted">Attacks from</span>
            {profiles.map((p) => (
              <button key={p.id} type="button" aria-pressed={profile === p.id} disabled={running} title={p.summary}
                onClick={() => { setProfile(p.id); try { window.localStorage.setItem("ts-profile", p.id); } catch { /* not remembered */ } }}>
                {p.name} <span className="ws-muted">· {p.kind}</span>
              </button>
            ))}
          </div>
        ) : null}
        {onlyScripted ? (
          <p className="ws-muted">
            No AI model is connected yet, so only the scripted baseline is available. Pull a model with Ollama (for example <code>ollama pull qwen2.5:7b-instruct</code>) and point ThreatSight at it on the <a href="/settings">Settings</a> page, or add a hosted model there; every model Ollama has pulled then shows up here.
          </p>
        ) : null}
        <div className="cmp-options">
          {options.map((o) => (
            <label key={o.id} className="cmp-option">
              <input
                type="checkbox"
                checked={chosen.includes(o.id)}
                disabled={running}
                onChange={(e) => setChosen((prev) => (e.target.checked ? [...prev, o.id] : prev.filter((x) => x !== o.id)))}
              />
              <span>{o.label}</span>
              <span className="cmp-kind">{o.id === "scripted" ? "no AI, fixed answers" : o.id.startsWith("local:") ? "local model" : "your agent"}</span>
            </label>
          ))}
        </div>
        <div className="cmp-run">
          <button type="button" className="ws-btn ws-btn-primary" disabled={running || chosen.length === 0 || chosen.length > 6} onClick={start}>
            {running ? "Comparing…" : `Compare ${chosen.length} model${chosen.length === 1 ? "" : "s"}`}
          </button>
          <span className="ws-muted">Up to 6 at a time. A local model takes a minute or two per model.</span>
        </div>
      </section>

      {job ? <Results job={job} /> : null}

      {owner ? (
        <section className="ws-panel">
          <h2 className="ws-h2">Test your own agent or a hosted model</h2>
          <p>
            Add OpenRouter, OpenAI, another Ollama server or your own agent&apos;s endpoint on the <a href="/settings">Settings</a> page.
            It then shows up in the list above for anyone signed in.
          </p>
        </section>
      ) : null}

      {jobs.length ? (
        <section className="ws-panel">
          <h2 className="ws-h2">Earlier comparisons</h2>
          <table className="ws-table">
            <thead>
              <tr><th>When</th><th>Organisation</th><th>Models</th><th>Status</th></tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id} className={j.id === job?.id ? "is-active" : undefined}>
                  <td><a href={`/compare?id=${j.id}`} onClick={(e) => { e.preventDefault(); window.history.replaceState(null, "", `/compare?id=${j.id}`); follow(j.id); }}>{j.created.replace("T", " ").replace("Z", "")}</a></td>
                  <td>{profiles.find((p) => p.id === (j.profile ?? "nordvik"))?.name ?? j.profile}</td>
                  <td>{j.models.map((m) => m.label).join(", ")}</td>
                  <td>{STATUS[j.status] ?? j.status}{j.status === "running" ? ` (${j.done} of ${j.total})` : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}
    </div>
  );
}

function Results({ job }: { job: Job }) {
  const running = job.status === "queued" || job.status === "running";
  const n = job.scenarios.length;
  return (
    <section className="ws-panel cmp-results">
      <header className="cmp-results-head">
        <h2 className="ws-h2">Results</h2>
        <span className={`cmp-status cmp-${job.status}`}>{STATUS[job.status]}{running ? `: ${job.done} of ${job.total} checks done` : ""}</span>
      </header>
      {running ? (
        <div className="cmp-progress" aria-hidden="true"><span style={{ width: `${(100 * job.done) / Math.max(1, job.total)}%` }} /></div>
      ) : null}
      {job.error ? <p className="ws-error">{job.error}</p> : null}

      {job.summary ? (
        <table className="ws-table cmp-summary">
          <thead>
            <tr><th>Model</th><th>Attacks that did harm, no guardrails</th><th>With the policy</th><th>Normal work still done</th></tr>
          </thead>
          <tbody>
            {job.summary.map((s) => (
              <tr key={s.model}>
                <td><strong>{s.label}</strong>{s.errors ? <span className="cmp-err"> · {s.errors} not reachable</span> : null}</td>
                <td className={s.harm_before ? "cmp-bad" : "cmp-good"}>{s.harm_before} of {s.scenarios - s.errors}</td>
                <td className={s.harm_after ? "cmp-bad" : "cmp-good"}>{s.harm_after} of {s.scenarios - s.errors}</td>
                <td>{s.work_total ? `${s.work_passed} of ${s.work_total}` : "–"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      <div className="cmp-matrix-wrap">
        <table className="cmp-matrix">
          <thead>
            <tr>
              <th scope="col">Attack</th>
              {job.models.map((m) => <th key={m.id} scope="col">{m.label}</th>)}
            </tr>
          </thead>
          <tbody>
            {job.scenarios.map((s) => (
              <tr key={s.id}>
                <th scope="row"><span className="cmp-agent">{s.agent}</span><span className="cmp-attack">{s.title}</span></th>
                {job.models.map((m) => {
                  const c = job.cells[`${s.id}|${m.id}`];
                  if (!c) return <td key={m.id} className="cmp-pending">{running ? "…" : "–"}</td>;
                  if (c.error) return <td key={m.id} className="cmp-cell" title={c.error}><span className="cmp-err">Not reachable</span></td>;
                  const b = outcome(c.before);
                  const a = outcome(c.after);
                  return (
                    <td key={m.id} className="cmp-cell" title={c.before?.said ? `It said: “${c.before.said}”` : undefined}>
                      <span className={`cmp-${b.tone}`}>{b.text}</span>
                      {c.before?.reason_code === "NO_ATTEMPT" && c.after?.reason_code === "NO_ATTEMPT" ? null : (
                        <>
                          <span className="cmp-arrow">with policy</span>
                          <span className={`cmp-${a.tone}`}>{a.text}</span>
                        </>
                      )}
                      {c.before?.calls.length ? <code className="cmp-calls">{Array.from(new Set(c.before.calls)).join(", ")}</code> : null}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="ws-muted cmp-foot">
        {n} attacks per model. &ldquo;Didn&apos;t take the bait&rdquo; means the model never tried the harmful action, so the policy was not needed.
        {job.evidence ? ` Every step is in a tamper-proof record of ${job.evidence.records} entries (${job.evidence.valid ? "checked: intact" : "check failed"}).` : ""}
      </p>
    </section>
  );
}
