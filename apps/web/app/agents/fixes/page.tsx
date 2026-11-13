"use client";

import { useCallback, useEffect, useState } from "react";

import "../agents.css";

// Verified remediation on the synthetic demo world (/api/world/remediation). A proposer picks one
// guardrail rule, the attack and its variants are replayed to prove it, and a named person applies
// it as a new policy version that can be rolled back. Nothing here touches a real system.

type Label = { synthetic: boolean; organisation: string; notice: string };
type Profile = { id: string; name: string; kind: string };
type Scenario = { id: string; title: string; agent: string; control: string; control_title: string };
type Rule = Record<string, unknown> & { id: string; tool: string; type: string };
type Tally = { FAIL: number; PASS: number; INCONCLUSIVE: number };
type Variant = { variant: number; verdict: string; reason_code: string };
type Proof = { proven: boolean; why: string; attack: { before: Tally; after: Tally }; variants: Variant[]; utility: { task: string; passed: boolean | null }[] };
type AttemptRow = { raw: unknown; rule: Rule | null; why: string; proof: Proof | null };
type HistoryRow = { action: string; by: string; at: string; version?: number; post_check?: { verdict: string; reason_code: string }; note?: string; reason?: string };
type Proposal = Label & {
  id: string;
  profile: string;
  created: string;
  scenario: string;
  title: string;
  agent: string;
  control: string;
  control_title: string;
  status: string;
  proposer: string;
  agent_model: string;
  base_version: number;
  finding: { failed: number; variants: Variant[] };
  attempts: AttemptRow[];
  rule: Rule | null;
  diff: string[];
  proof: Proof | null;
  history: HistoryRow[];
  rollback_until?: string;
  evidence: { records: number; head: string; valid: boolean; message: string };
};
type ProposalRow = { id: string; created: string; scenario: string; title: string; agent: string; status: string; proposer: string };
type Version = { version: number; parent: number | null; created: string; by: string; proposal: string; change: { op: string; rule?: Rule; rule_id?: string; reason?: string }; diff: string[] };
type View = Label & {
  profile: string;
  live: { version: number; policy: { rules: Rule[] } };
  versions: Version[];
  proposals: ProposalRow[];
  proposers: string[];
  live_model: string | null;
  disabled: boolean;
};

async function getJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { cache: "no-store", ...init });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || body.detail || `${response.status} ${response.statusText}`);
  return body as T;
}

function post<T>(path: string, body: unknown): Promise<T> {
  return getJson<T>(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

const STATUS: Record<string, { label: string; tone: string }> = {
  proposed: { label: "Proven, waiting for approval", tone: "exposed" },
  applied: { label: "Applied", tone: "fixed" },
  rolled_back: { label: "Rolled back", tone: "muted" },
  rejected: { label: "Rejected", tone: "muted" },
  no_proven_fix: { label: "No proven fix, open for a person", tone: "proven" },
  nothing_to_fix: { label: "Nothing to fix", tone: "fixed" },
};

const RULE_TEXT: Record<string, string> = {
  requester_owns_case: "Only the case owner may read a case",
  requester_owns_tenant: "Only a member of a tenant may read it",
  supplier_registered: "Money only goes to an account already on file",
  max_amount_without_approver: "Amounts above a limit need a named approver",
  allow_actions: "The tool may only run the listed actions",
  internal_recipients_only: "Email only inside the organisation",
};

function ruleSentence(rule: Rule) {
  const base = RULE_TEXT[rule.type] ?? rule.type;
  const extra = rule.type === "allow_actions" ? `: ${(rule.actions as string[]).join(", ")}` : rule.type === "max_amount_without_approver" ? ` (${rule.limit})` : "";
  const mode = rule.on_fail === "hold" ? "Otherwise the call waits for a person." : "Otherwise the call is refused.";
  return `${base}${extra}. ${mode}`;
}

function initialProfile(): string {
  if (typeof window === "undefined") return "nordvik";
  return new URLSearchParams(window.location.search).get("profile") || "nordvik";
}

function StatusChip({ status }: { status: string }) {
  const s = STATUS[status] ?? { label: status, tone: "muted" };
  return <span className={`ws-chip ws-${s.tone}`}>{s.label}</span>;
}

function ProposalCard({ p, disabled, onAct }: { p: Proposal; disabled: boolean; onAct: (action: "apply" | "reject" | "rollback", approver: string) => Promise<void> }) {
  const [approver, setApprover] = useState("Ingrid Dahl, security (demo)");
  const [busy, setBusy] = useState(false);
  const go = async (action: "apply" | "reject" | "rollback") => {
    setBusy(true);
    try {
      await onAct(action, approver);
    } finally {
      setBusy(false);
    }
  };
  const canAct = p.status === "proposed" || p.status === "applied";
  return (
    <section className={`ws-panel ws-border-${STATUS[p.status]?.tone ?? "exposed"}`} aria-label="Proposed fix">
      <header className="ws-console-head">
        <div>
          <p className="ws-eyebrow">Proposed fix · {p.agent}</p>
          <h2 className="ws-h2">{p.title}</h2>
          <p className="ws-muted ws-small">
            {p.control}: {p.control_title}. Proposed by {p.proposer === "heuristic" ? "the built-in rules (no AI model)" : p.proposer}, replayed with {p.agent_model}, against policy v{p.base_version}.
          </p>
        </div>
        <StatusChip status={p.status} />
      </header>

      <p>
        <strong>Finding.</strong> {p.finding.failed} of {p.finding.variants.length} phrasings of the attack caused harm under the live policy.
      </p>

      {p.rule ? (
        <>
          <p>
            <strong>Fix.</strong> Add one rule on <code>{p.rule.tool}</code>: {ruleSentence(p.rule)}
          </p>
          <pre className="ws-diff" aria-label="Policy change">{p.diff.join("\n")}</pre>
        </>
      ) : null}

      {p.proof ? (
        <div className="ws-proof">
          <div>
            <span className="ws-eyebrow">Attack replayed, before → after</span>
            <span>
              <span className="ws-proven">{p.proof.attack.before.FAIL} harmful</span> → <span className={p.proof.attack.after.FAIL ? "ws-proven" : "ws-fixed"}>{p.proof.attack.after.FAIL} harmful</span>
              <span className="ws-muted"> · {p.proof.attack.after.PASS} stopped by the new rule</span>
            </span>
          </div>
          <div>
            <span className="ws-eyebrow">Normal work still runs</span>
            {p.proof.utility.map((u) => (
              <span key={u.task} className={`ws-chip ws-${u.passed ? "fixed" : u.passed === false ? "proven" : "exposed"}`}>
                {u.passed ? "✓" : u.passed === false ? "✗" : "?"} {u.task}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {p.attempts.length > 1 || (p.attempts.length === 1 && !p.attempts[0].proof?.proven) ? (
        <details>
          <summary>Candidates tried ({p.attempts.length})</summary>
          <ol className="ws-small">
            {p.attempts.map((a, i) => (
              <li key={i}>
                <code>{a.rule ? a.rule.id : JSON.stringify(a.raw)}</code> <span className={a.proof?.proven ? "ws-fixed" : "ws-proven"}>{a.why}</span>
              </li>
            ))}
          </ol>
        </details>
      ) : null}

      {p.history.length ? (
        <ul className="ws-small">
          {p.history.map((h, i) => (
            <li key={i}>
              <strong>{h.action.replace("_", " ")}</strong> by {h.by} at {h.at.replace("T", " ").replace("Z", "")}
              {h.version ? ` → policy v${h.version}` : ""}
              {h.post_check ? ` · attack re-run on the live policy: ${h.post_check.verdict === "FAIL" ? "harm" : "stopped"}` : ""}
              {h.reason ? ` · ${h.reason}` : ""}
            </li>
          ))}
        </ul>
      ) : null}

      {canAct ? (
        <div className="ws-approval ws-border-exposed">
          <label className="ws-model">
            Approver
            <input value={approver} maxLength={80} onChange={(e) => setApprover(e.target.value)} />
          </label>
          {p.status === "proposed" ? (
            <>
              <button type="button" className="ws-btn ws-btn-small" disabled={busy || !approver.trim()} onClick={() => go("reject")}>Reject</button>
              <button type="button" className="ws-btn ws-btn-small ws-btn-primary" disabled={busy || disabled || !approver.trim()} onClick={() => go("apply")}>
                {busy ? "Applying…" : "Apply fix"}
              </button>
            </>
          ) : (
            <button type="button" className="ws-btn ws-btn-small" disabled={busy || !approver.trim()} onClick={() => go("rollback")} title={p.rollback_until ? `Possible until ${p.rollback_until}` : undefined}>
              Roll back
            </button>
          )}
        </div>
      ) : null}

      <footer className="ws-evidence">
        <span className="ws-eyebrow">Tamper-proof record</span>
        <span className="ws-muted">{p.evidence.records} entries, {p.evidence.valid ? "chain intact" : p.evidence.message}</span>
        <a className="ws-btn ws-btn-small" href={`/api/world/remediation/${p.id}/evidence.jsonl?profile=${encodeURIComponent(p.profile)}`}>Download evidence</a>
      </footer>
    </section>
  );
}

export default function FixesPage() {
  const [profile, setProfile] = useState(initialProfile);
  const [profilesList, setProfiles] = useState<Profile[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [view, setView] = useState<View | null>(null);
  const [scenario, setScenario] = useState("");
  const [proposer, setProposer] = useState("heuristic");
  const [current, setCurrent] = useState<Proposal | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async (p: string) => {
    setView(await getJson<View>(`/api/world/remediation?profile=${p}`));
  }, []);

  useEffect(() => {
    getJson<{ profiles: Profile[] }>("/api/world/profiles").then((r) => setProfiles(r.profiles)).catch(() => undefined);
  }, []);

  useEffect(() => {
    setError("");
    setCurrent(null);
    getJson<{ scenarios: Scenario[] }>(`/api/world/scenarios?profile=${profile}`)
      .then((r) => {
        setScenarios(r.scenarios);
        setScenario(r.scenarios[0]?.id ?? "");
      })
      .catch((e: Error) => setError(e.message));
    refresh(profile).catch((e: Error) => setError(e.message));
  }, [profile, refresh]);

  async function propose() {
    setBusy(true);
    setError("");
    try {
      setCurrent(await post<Proposal>("/api/world/remediation", { profile, scenario, proposer }));
      await refresh(profile);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function open(id: string) {
    setError("");
    try {
      setCurrent(await getJson<Proposal>(`/api/world/remediation/${id}?profile=${profile}`));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function act(action: "apply" | "reject" | "rollback", approver: string) {
    if (!current) return;
    setError("");
    try {
      setCurrent(await post<Proposal>(`/api/world/remediation/${current.id}/${action}`, { profile, approver }));
      await refresh(profile);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const rules = view?.live.policy.rules ?? [];

  return (
    <div className="ws">
      <div className="ws-banner" role="note">
        <span className="ws-banner-tag">Demo</span>
        <span>{view?.organisation ?? "A fictional organisation"}. Fixes change only the demo world&apos;s policy, never a real system.</span>
      </div>

      <div className="ws-profile" role="group" aria-label="Organisation">
        <span className="ws-muted">Organisation</span>
        {profilesList.map((p) => (
          <button key={p.id} type="button" aria-pressed={profile === p.id} onClick={() => setProfile(p.id)}>
            {p.name} <span className="ws-muted">· {p.kind}</span>
          </button>
        ))}
      </div>

      <header className="ws-head">
        <div>
          <h1 className="ws-title">Fixes that are proven before you apply them</h1>
          <ol className="ws-steps">
            <li><strong>Propose.</strong> One guardrail rule is picked from a fixed catalog. The AI model never writes rules or code.</li>
            <li><strong>Prove.</strong> The attack, five more phrasings of it and the agent&apos;s normal work are replayed with the rule on.</li>
            <li><strong>Approve.</strong> A named person applies it as a new policy version, the attack runs again, and it can be rolled back.</li>
          </ol>
        </div>
      </header>

      {error ? <p className="ws-error">{error}</p> : null}
      {view?.disabled ? <p className="ws-error">Applying fixes is switched off on this server.</p> : null}

      <section className="ws-panel">
        <div className="ws-actions">
          <label className="ws-model">
            Attack
            <select value={scenario} onChange={(e) => setScenario(e.target.value)}>
              {scenarios.map((s) => (
                <option key={s.id} value={s.id}>{s.agent}: {s.title}</option>
              ))}
            </select>
          </label>
          <label className="ws-model">
            Proposed by
            <select value={proposer} onChange={(e) => setProposer(e.target.value)}>
              {(view?.proposers ?? ["heuristic"]).map((p) => (
                <option key={p} value={p}>{p === "live" ? `AI model: ${view?.live_model} (set in Settings)` : "Built-in rules (no AI model)"}</option>
              ))}
            </select>
          </label>
          <button type="button" className="ws-btn ws-btn-primary" disabled={busy || !scenario} onClick={propose}>
            {busy ? "Finding and proving…" : "Find and propose a fix"}
          </button>
        </div>
        <p className="ws-muted ws-small">
          Live policy v{view?.live.version ?? 0}: {rules.length === 0 ? "no guardrails yet (an open gateway)." : `${rules.length} rule${rules.length > 1 ? "s" : ""}.`}
        </p>
        {rules.length ? (
          <ul className="ws-small">
            {rules.map((r) => (
              <li key={r.id}><code>{r.tool}</code>: {ruleSentence(r)}</li>
            ))}
          </ul>
        ) : null}
      </section>

      {current ? <ProposalCard p={current} disabled={Boolean(view?.disabled)} onAct={act} /> : null}

      {view && view.proposals.length ? (
        <section className="ws-panel">
          <p className="ws-eyebrow">Proposals</p>
          <table className="ws-table">
            <thead>
              <tr><th>When (UTC)</th><th>Agent</th><th>Attack</th><th>Status</th></tr>
            </thead>
            <tbody>
              {view.proposals.map((r) => (
                <tr key={r.id} onClick={() => open(r.id)} className={current?.id === r.id ? "is-active" : undefined}>
                  <td className="ws-mono">{r.created.replace("T", " ").replace("Z", "")}</td>
                  <td>{r.agent}</td>
                  <td>{r.title}</td>
                  <td><StatusChip status={r.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}

      {view && view.versions.length ? (
        <section className="ws-panel">
          <p className="ws-eyebrow">Policy history</p>
          <table className="ws-table">
            <thead>
              <tr><th>Version</th><th>When (UTC)</th><th>Change</th><th>By</th></tr>
            </thead>
            <tbody>
              {view.versions.map((v) => (
                <tr key={v.version}>
                  <td className="ws-mono">v{v.version}</td>
                  <td className="ws-mono">{v.created.replace("T", " ").replace("Z", "")}</td>
                  <td>{v.change.op === "add_rule" ? "Added" : "Removed"} <code>{v.change.rule?.id ?? v.change.rule_id}</code>{v.change.reason ? ` (${v.change.reason})` : ""}</td>
                  <td>{v.by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}
    </div>
  );
}
