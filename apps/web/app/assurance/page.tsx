"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { ConfirmButton } from "@/components/ConfirmButton";
import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";
import { verdictTone } from "@/lib/status";

type Run = {
  id: string;
  scenario_key: string;
  verdict: string;
  reason_code: string;
  finding_id: string | null;
  evidence_id: string | null;
  parent_run_id: string | null;
  narration: string | null;
  observation: {
    tool_name?: string;
    gateway_decision?: string;
    executed?: boolean;
    completed_side_effect?: string | null;
  };
  finished_at: string | null;
};

type Status = {
  execution_engine: string;
  adapter: string;
  agent: { authorization_mode?: string; error?: string };
  evaluator: string;
};

type Bootstrap = { system_id: string; control_id: string };

type Finding = { id: string; status: string };

export default function AssurancePage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [failFinding, setFailFinding] = useState<Finding | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [readOnly, setReadOnly] = useState(true);

  useEffect(() => {
    api<{ role: string }>("/api/v1/radar/workspace")
      .then((body) => setReadOnly(body.role === "viewer" || body.role === "auditor"))
      .catch(() => setReadOnly(true));
  }, []);

  async function load() {
    const [st, history] = await Promise.all([
      api<Status>("/api/v1/assurance/status"),
      api<Run[]>("/api/v1/assurance/runs"),
    ]);
    setStatus(st);
    setRuns(history);
    const fail = history.find((item) => item.scenario_key === "AUTH-01" && item.verdict === "FAIL");
    if (fail?.finding_id) {
      setFailFinding(await api<Finding>(`/api/v1/findings/${fail.finding_id}`));
    } else {
      setFailFinding(null);
    }
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, []);

  async function prepare() {
    setError(null);
    setBusy(true);
    try {
      const body = await api<Bootstrap>("/api/v1/assurance/demo/bootstrap", { method: "POST" });
      setBootstrap(body);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bootstrap failed");
    } finally {
      setBusy(false);
    }
  }

  async function runScenario(scenario_key: string, parent_run_id?: string) {
    setError(null);
    setBusy(true);
    try {
      if (!bootstrap) {
        const body = await api<Bootstrap>("/api/v1/assurance/demo/bootstrap", { method: "POST" });
        setBootstrap(body);
      }
      await api<Run>("/api/v1/assurance/runs", {
        method: "POST",
        body: JSON.stringify({
          scenario_key,
          confirm_execution: true,
          parent_run_id: parent_run_id || null,
        }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Run failed");
    } finally {
      setBusy(false);
    }
  }

  async function remediate(findingId: string) {
    setError(null);
    setBusy(true);
    try {
      await api(`/api/v1/findings/${findingId}/remediate`, { method: "POST" });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Remediation failed");
    } finally {
      setBusy(false);
    }
  }

  const latestFail = runs.find((item) => item.scenario_key === "AUTH-01" && item.verdict === "FAIL");
  const remediated = failFinding?.status === "remediated" || failFinding?.status === "resolved";
  const auth02Parent = remediated ? latestFail?.id : undefined;

  return (
    <div className="stack">
      <PageHeader
        kicker="CTRL-002 tests"
        title="Tool authorization"
        lede="First test (AUTH-01): ask the synthetic support agent to cancel another customer's order and record what actually happened. If it succeeds, enable an authorization check, then run the same test again (AUTH-02). Verdicts come from observed tool impact, not what the model says about itself."
      />
      <ErrorBanner message={error} />
      <section className="card">
        <h2>Demo target</h2>
        <p>
          Engine: <span className="pill">{status?.execution_engine || "…"}</span> · Adapter{" "}
          {status?.adapter} · Mode {status?.agent.authorization_mode || status?.agent.error || "unknown"} · Evaluator{" "}
          {status?.evaluator}
        </p>
        <p className="lede">Synthetic tools and orders only. No host filesystem, email, or external targets.</p>
        {readOnly ? <p>Recorded assurance runs stay visible. This demonstration cannot prepare, run, or change a test.</p> : (
        <button className="btn" type="button" onClick={() => void prepare()} disabled={busy}>
          {busy ? "Working…" : "Prepare CTRL-002 demo"}
        </button>
        )}
      </section>
      <section>
        <h2>Run tests</h2>
        {readOnly ? <p>A visitor cannot run or remediate a test.</p> : !latestFail ? (
          <button className="btn" type="button" disabled={busy} onClick={() => void runScenario("AUTH-01")}>
            Run AUTH-01 unauthorized cancel
          </button>
        ) : !remediated ? (
          latestFail.finding_id ? (
            <ConfirmButton
              label="Enable authorization gateway"
              confirmLabel="Confirm gateway enable"
              disabled={busy}
              onConfirm={() => void remediate(latestFail.finding_id!)}
            />
          ) : (
            <p className="muted">AUTH-01 FAIL is recorded. Open the finding to enable the authorization gateway.</p>
          )
        ) : (
          <button
            className="btn"
            type="button"
            disabled={busy}
            onClick={() => void runScenario("AUTH-02", auth02Parent)}
          >
            Run AUTH-02 authorized cancel
          </button>
        )}
      </section>
      <section>
        <h2>Runs</h2>
        {runs.length === 0 ? (
          <EmptyState title="No runs yet" detail="Open Showcase to load the labelled demo, then confirm AUTH-01 here." />
        ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Scenario</th>
              <th>Verdict</th>
              <th>Reason</th>
              <th>Impact</th>
              <th>Links</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((item) => (
              <tr key={item.id}>
                <td>
                  {item.scenario_key}
                  {item.parent_run_id ? " (retest)" : ""}
                </td>
                <td>
                  <StatusPill value={item.verdict} tone={verdictTone(item.verdict)} />
                </td>
                <td>{item.reason_code}</td>
                <td>
                  {item.observation.tool_name || "—"} · {item.observation.gateway_decision || "—"} ·{" "}
                  {item.observation.completed_side_effect || "no side effect"}
                </td>
                <td>
                  {item.finding_id ? <Link href={`/findings/${item.finding_id}`}>finding</Link> : null}
                  {item.evidence_id ? (
                    <>
                      {" "}
                      · <Link href={`/evidence/${item.evidence_id}`}>evidence</Link>
                    </>
                  ) : null}
                  {bootstrap ? (
                    <>
                      {" "}
                      · <Link href={`/controls/${bootstrap.control_id}`}>control</Link>
                    </>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        )}
      </section>
    </div>
  );
}
