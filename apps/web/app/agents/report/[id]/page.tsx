"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import "../../agents.css";
import "./report.css";

// One-page assessment for a single demo run, made to be read by someone who was not in the room
// and saved as a PDF from the browser's print dialog. Everything comes from the demo-world service.

type Verdict = { verdict: string; reason_code: string; summary: string };
type ToolCall = { name: string; args: Record<string, unknown>; executed: boolean; held?: boolean; rule: string | null };
type Event = { type: string; content?: string; text?: string };
type Assessment = { model: string; policy: string; verdict: Verdict; tool_calls: ToolCall[]; transcript: Event[] };
type Approval = { run: number; call: number; decision: string; approver: string; decided: string; verdict: Verdict };
type Run = {
  id: string;
  created: string;
  scenario: string;
  title: string;
  agent: string;
  control: string;
  mode: string;
  runs: Assessment[];
  utility?: { task: string; passed: boolean | null }[];
  evidence: { records: number; head: string; signed: boolean };
  approvals?: Approval[];
  organisation: string;
  profile?: string;
};
type Scenario = { id: string; control_title: string; tags: string[]; agentic?: string[]; atlas?: string[]; attack_message: string };
type Agent = { id: string; score: number; worst_path: { input: string; tool: string; data: string }; tools: { name: string; guarded: boolean }[] };
type Graph = { agents: Agent[] };

const RESULT: Record<string, string> = { FAIL: "Harm done", PASS: "Stopped", INCONCLUSIVE: "No attack tried" };

function policyName(policy: string) {
  if (policy === "open") return "No guardrails";
  if (policy === "nordvik-hardened") return "Nordvik policy (all guardrails)";
  if (policy === "helio-hardened") return "Helio Cloud policy (all guardrails)";
  if (policy.startsWith("custom:")) return `Guardrails on ${policy.slice(7).split(",").join(", ")}`;
  return policy;
}

function graphQuery(policy: string, profile: string) {
  if (policy.startsWith("custom:")) return `profile=${profile}&policy=custom&guard=${encodeURIComponent(policy.slice(7))}`;
  return `profile=${profile}&policy=${encodeURIComponent(policy)}`;
}

function headline(runs: Assessment[]) {
  const v = runs.map((r) => r.verdict.verdict);
  if (v.length === 2 && v[0] === "FAIL" && v[1] === "PASS") return "the attack did harm, and the fix stopped it";
  if (v.length === 2 && v[1] === "FAIL") return "the attack still did harm after the fix";
  if (v.at(-1) === "FAIL") return "the attack did harm";
  if (v.at(-1) === "PASS") return "the attack was stopped";
  return "the agent did not attempt the attack";
}

function said(a: Assessment) {
  const e = a.transcript.find((x) => x.type === "assistant" && (x.content || x.text));
  return e ? (e.content || e.text || "").trim() : "";
}

function callText(c: ToolCall) {
  return `${c.name}(${Object.entries(c.args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ")})`;
}

function callState(c: ToolCall) {
  if (c.executed) return "Done";
  if (c.held) return "Paused for a named approver";
  return "Blocked by policy";
}

function tone(v: string) {
  return v === "FAIL" ? "proven" : v === "PASS" ? "fixed" : "exposed";
}

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const [run, setRun] = useState<Run | null>(null);
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [scores, setScores] = useState<{ before?: Agent; after?: Agent }>({});
  const [valid, setValid] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const get = async <T,>(path: string): Promise<T> => {
      const r = await fetch(path, { cache: "no-store" });
      if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
      return r.json() as Promise<T>;
    };
    (async () => {
      const r = await get<Run>(`/api/world/runs/${encodeURIComponent(id)}`);
      setRun(r);
      const profile = r.profile ?? "nordvik";
      const [sc, open, after, check] = await Promise.all([
        get<{ scenarios: Scenario[] }>("/api/world/scenarios"),
        get<Graph>(`/api/world/graph?${graphQuery(r.runs[0].policy, profile)}`),
        get<Graph>(`/api/world/graph?${graphQuery(r.runs[r.runs.length - 1].policy, profile)}`),
        get<{ valid: boolean }>(`/api/world/runs/${encodeURIComponent(id)}/verify`),
      ]);
      setScenario(sc.scenarios.find((s) => s.id === r.scenario) ?? null);
      setScores({ before: open.agents.find((a) => a.id === r.scenario), after: after.agents.find((a) => a.id === r.scenario) });
      setValid(check.valid);
    })().catch((e: Error) => setError(e.message));
  }, [id]);

  if (error) return <p className="auth-error">Could not load this run: {error}</p>;
  if (!run) return <p className="muted">Loading the report…</p>;

  const first = run.runs[0];
  const last = run.runs[run.runs.length - 1];
  const twoRuns = run.runs.length > 1;
  const utility = run.utility ?? [];
  const kept = utility.filter((u) => u.passed).length;
  const rulesFired = Array.from(new Set(last.tool_calls.filter((c) => !c.executed && c.rule).map((c) => c.rule as string)));
  const guarded = scores.after?.tools.filter((t) => t.guarded).map((t) => t.name) ?? [];
  const date = run.created.slice(0, 10);

  return (
    <div className="report">
      <div className="report-toolbar">
        <Link className="btn secondary" href="/agents">
          Back to Agent blast radius
        </Link>
        <button className="btn" type="button" onClick={() => window.print()}>
          Save as PDF
        </button>
        <a className="btn secondary" href={`/api/world/runs/${encodeURIComponent(run.id)}/inspect.json`} download>
          Inspect AI log
        </a>
      </div>

      <article className="report-page">
        <header className="report-head">
          <span>ThreatSight · Agent assessment</span>
          <span>{date}</span>
          <span>{run.organisation}</span>
        </header>

        <h1>
          {run.agent}: {headline(run.runs)}
        </h1>

        <div className="report-figures">
          <div>
            <span className="report-label">Risk score</span>
            <strong>
              {scores.before?.score ?? "…"}
              {twoRuns ? <> → {scores.after?.score ?? "…"}</> : null}
            </strong>
            <span className="report-note">out of 100, from the tools it holds and the data they reach</span>
          </div>
          <div>
            <span className="report-label">Result</span>
            <strong>
              <span className={`ws-${tone(first.verdict.verdict)}`}>{RESULT[first.verdict.verdict] ?? first.verdict.verdict}</span>
              {twoRuns ? (
                <>
                  {" "}
                  → <span className={`ws-${tone(last.verdict.verdict)}`}>{RESULT[last.verdict.verdict] ?? last.verdict.verdict}</span>
                </>
              ) : null}
            </strong>
            <span className="report-note">{twoRuns ? "before → after the fix" : policyName(last.policy)}</span>
          </div>
          <div>
            <span className="report-label">Normal work</span>
            <strong>{utility.length ? `${kept} of ${utility.length} still run` : "not checked"}</strong>
            <span className="report-note">the fix must not stop legitimate tasks</span>
          </div>
        </div>

        <section>
          <h2>What we tested</h2>
          <p>
            <strong>{run.title}.</strong> {scenario?.control_title ?? ""} ({run.control}
            {scenario?.tags.length ? `; ${scenario.tags.join(", ")}` : ""}).
          </p>
          {scenario?.atlas?.length || scenario?.agentic?.length ? (
            <p className="report-note">
              {scenario.atlas?.length ? <>MITRE ATLAS: {scenario.atlas.join(", ")}. </> : null}
              {scenario.agentic?.length ? <>OWASP Agentic: {scenario.agentic.join(", ")}.</> : null}
            </p>
          ) : null}
          {scores.before ? (
            <p>
              Worst case: <strong>{scores.before.worst_path.input}</strong> → <code>{scores.before.worst_path.tool}</code> →{" "}
              <strong>{scores.before.worst_path.data}</strong>
            </p>
          ) : null}
          {scenario ? <blockquote className="report-quote">{scenario.attack_message}</blockquote> : null}
        </section>

        <section className={`report-cols report-cols-${run.runs.length}`}>
          {run.runs.map((a, i) => (
            <div key={i} className={`report-col ws-border-${tone(a.verdict.verdict)}`}>
              <h3>
                {twoRuns ? (i === 0 ? "Before the fix" : "After the fix") : "Result"} · {policyName(a.policy)}
              </h3>
              <p className="report-said">
                <span className="report-label">Agent replied</span> {said(a) || "(no reply, it only acted)"}
              </p>
              <p className="report-label">What it actually did</p>
              <ul className="report-calls">
                {a.tool_calls.length === 0 ? <li>It took no action.</li> : null}
                {a.tool_calls.map((c, j) => (
                  <li key={j}>
                    <code>{callText(c)}</code> <span className="report-state">{callState(c)}</span>
                  </li>
                ))}
              </ul>
              <p className="report-verdict">
                <strong className={`ws-${tone(a.verdict.verdict)}`}>{RESULT[a.verdict.verdict] ?? a.verdict.verdict}.</strong> {a.verdict.summary}
              </p>
            </div>
          ))}
        </section>

        {twoRuns ? (
          <section>
            <h2>The fix</h2>
            <p>
              {policyName(last.policy)}.{" "}
              {guarded.length ? (
                <>
                  Tools under a guardrail: <code>{guarded.join(", ")}</code>.
                </>
              ) : null}{" "}
              {rulesFired.length ? (
                <>
                  Rules that acted in the attack: <code>{rulesFired.join(", ")}</code>.
                </>
              ) : null}
            </p>
            {utility.length ? <p className="report-note">Normal work checked: {utility.map((u) => `${u.passed ? "✓" : "✗"} ${u.task}`).join(" · ")}</p> : null}
          </section>
        ) : null}

        {run.approvals?.length ? (
          <section>
            <h2>Human decisions</h2>
            <ul>
              {run.approvals.map((a, i) => (
                <li key={i}>
                  {a.approver} {a.decision === "approve" ? "approved" : "rejected"} the held call on {a.decided.slice(0, 16).replace("T", " ")} UTC. {a.verdict.summary}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <section>
          <h2>Proof</h2>
          <p>
            Every step was written to a tamper-proof record of {run.evidence.records} entries, each linked to the one before
            {run.evidence.signed ? " and signed" : ""}.{" "}
            {valid === null ? "Checking it…" : valid ? "Checked when this report was made: intact." : "Checked when this report was made: it has been changed."}
          </p>
          <p className="report-note">
            Run <code>{run.id}</code> · record head <code>{run.evidence.head.slice(0, 16)}…</code> · model {last.model}
          </p>
        </section>

        <footer className="report-foot">
          Judged only on what the agent actually did to the systems, never on what it said. {run.organisation} and all its data are
          made up. This is technical assurance from a prototype, not a legal compliance result.
        </footer>
      </article>
    </div>
  );
}
