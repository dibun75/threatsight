"use client";

import Link from "next/link";
import { useParams, usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { ConfirmButton } from "@/components/ConfirmButton";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";
import { findingStatusTone, severityTone, verdictTone } from "@/lib/status";

type Finding = {
  id: string;
  title: string;
  status: string;
  severity: string;
  verdict: string;
  summary: string;
  control_id: string;
  ai_system_id: string;
  run_id: string;
  evidence_id: string | null;
  resolved_run_id: string | null;
  ai_system_name: string | null;
  ai_system_display_name?: string | null;
  control_identifier: string | null;
};

type Run = {
  id: string;
  verdict: string;
  reason_code: string;
  narration: string | null;
  observation: Record<string, unknown>;
  parent_run_id: string | null;
};

type Evidence = { id: string; integrity_hash: string | null; envelope: Record<string, unknown> | null };
type Remediation = { id: string; action: string; detail: string; actor: string; created_at: string };

export default function FindingDetailPage() {
  const params = useParams<{ id: string }>();
  const pathname = usePathname();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  const [retest, setRetest] = useState<Run | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [readOnly, setReadOnly] = useState(true);

  async function load() {
    const item = await api<Finding>(`/api/v1/findings/${params.id}`);
    setFinding(item);
    const runRow = await api<Run>(`/api/v1/assurance/runs/${item.run_id}`);
    setRun(runRow);
    if (item.evidence_id) {
      setEvidence(await api<Evidence>(`/api/v1/evidence/${item.evidence_id}`));
    }
    setRemediations(await api<Remediation[]>(`/api/v1/findings/${item.id}/remediations`));
    if (item.resolved_run_id) {
      setRetest(await api<Run>(`/api/v1/assurance/runs/${item.resolved_run_id}`));
    } else {
      setRetest(null);
    }
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [params.id]);

  useEffect(() => {
    api<{ role: string }>("/api/v1/radar/workspace")
      .then((body) => setReadOnly(body.role === "viewer" || body.role === "auditor"))
      .catch(() => setReadOnly(true));
  }, []);

  async function remediate() {
    setBusy(true);
    setError(null);
    try {
      await api(`/api/v1/findings/${params.id}/remediate`, { method: "POST" });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Remediation failed");
    } finally {
      setBusy(false);
    }
  }

  async function runRetest() {
    if (!finding) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api("/api/v1/assurance/runs", {
        method: "POST",
        body: JSON.stringify({
          scenario_key: "AUTH-02",
          confirm_execution: true,
          parent_run_id: finding.run_id,
        }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Retest failed");
    } finally {
      setBusy(false);
    }
  }

  if (!finding) {
    return error ? <ErrorBanner message={error} /> : <LoadingState />;
  }

  const observation = run?.observation || {};
  return (
    <div className="stack">
      <PageHeader
        kicker="Finding"
        title={finding.title}
        lede={finding.summary}
        crumbs={[{ href: pathname.startsWith("/actions") ? "/actions" : "/findings", label: pathname.startsWith("/actions") ? "Actions" : "Findings" }, { label: finding.title }]}
      />
      <p>
        <StatusPill value={finding.verdict} tone={verdictTone(finding.verdict)} />{" "}
        <StatusPill value={finding.severity} tone={severityTone(finding.severity)} />{" "}
        <StatusPill value={finding.status} tone={findingStatusTone(finding.status)} />
      </p>
      <p>
        System:{" "}
        <Link href={`/systems/${finding.ai_system_id}`}>
          {finding.ai_system_display_name || finding.ai_system_name || "system"}
        </Link>{" "}
        · Control:{" "}
        <Link href={`/controls/${finding.control_id}`}>{finding.control_identifier || "control"}</Link>
        {finding.evidence_id ? (
          <>
            {" "}
            · <Link href={`/evidence/${finding.evidence_id}`}>Evidence</Link>
          </>
        ) : null}
      </p>
      <ErrorBanner message={error} />
      {run && (
        <section className="card">
          <h2>Observed action and impact</h2>
          <p>Reason: {run.reason_code}</p>
          <p>
            Tool {String(observation.tool_name || "—")} · gateway {String(observation.gateway_decision || "—")} · impact{" "}
            {String(observation.completed_side_effect || "none")}
          </p>
          <p className="lede">Narration (ignored by the evaluator): {run.narration || "—"}</p>
        </section>
      )}
      {evidence?.integrity_hash && (
        <section className="card">
          <h2>Evidence</h2>
          <p>
            SHA-256: <code>{evidence.integrity_hash}</code>
          </p>
          <p>
            <Link href={`/evidence/${evidence.id}`}>Open envelope</Link>
          </p>
        </section>
      )}
      <section>
        <h2>Remediation</h2>
        {remediations.length === 0 ? <p className="muted">No remediation recorded.</p> : null}
        <ul>
          {remediations.map((item) => (
            <li key={item.id}>
              {item.action === "enable_gateway_authorization" ? "Authorization gateway enabled" : item.action.replaceAll("_", " ")}{" "}
              — {item.detail}
            </li>
          ))}
        </ul>
      </section>
      {retest && (
        <section className="card">
          <h2>AUTH-02 result</h2>
          <p>
            <StatusPill value={retest.verdict} tone={verdictTone(retest.verdict)} /> {retest.reason_code}
          </p>
        </section>
      )}
      {readOnly ? (
        <p>Recorded remediation stays visible. This demonstration cannot enable a control or run a retest.</p>
      ) : finding.status !== "resolved" ? (
        <p>
          {finding.status === "open" ? (
            <ConfirmButton
              label="Enable authorization gateway"
              confirmLabel="Confirm gateway enable"
              disabled={busy}
              onConfirm={() => void remediate()}
            />
          ) : (
            <ConfirmButton
              label="Run AUTH-02"
              confirmLabel="Confirm AUTH-02"
              disabled={busy}
              onConfirm={() => void runRetest()}
            />
          )}
        </p>
      ) : null}
    </div>
  );
}
