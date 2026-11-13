"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { ConfirmButton } from "@/components/ConfirmButton";
import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";
import { assuranceTone, findingStatusTone, verdictTone } from "@/lib/status";

type Posture = {
  legal_compliance_claim: boolean;
  system: {
    id: string;
    name: string;
    display_name?: string;
    organisation?: string | null;
    technical_identifier?: string;
    origin_label?: string;
    labelled_synthetic?: boolean;
    description: string | null;
    owner: string;
    team: string | null;
    environment: string;
    lifecycle: string;
    risk_classification: string | null;
  };
  identity?: {
    display_name?: string;
    organisation?: string | null;
    technical_identifier?: string;
    origin_label?: string;
    labelled_synthetic?: boolean;
  };
  posture_summary?: string;
  profile: { purpose: string; labelled_synthetic: boolean } | null;
  capabilities: Array<string | { name: string; kind?: string }>;
  data_categories: string[];
  users_subjects: string[];
  traces: Array<{
    id: string;
    source_kind: string;
    tool_name: string | null;
    labelled_synthetic: boolean;
    authorization_context: { authorized?: boolean };
    occurred_at: string | null;
  }>;
  threat_exposure: Array<{
    threat_key: string | null;
    threat_title: string | null;
    technique_key: string;
    technique_title: string;
    affected_capability: string;
    href: string;
  }>;
  missing_information: string[];
  tests: Array<{
    id: string;
    scenario_key: string;
    verdict: string;
    reason_code: string;
    parent_run_id: string | null;
  }>;
  remediation_state: { open: number; remediated: number; resolved: number; latest_verdict: string };
  controls: Array<{
    id: string;
    identifier: string;
    title: string;
    assurance_status: string;
    latest_verdict: string | null;
  }>;
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    verdict: string;
  }>;
  evidence: Array<{ id: string; title: string; integrity_hash: string | null }>;
  requirements: Array<{ id: string; title: string; status: string }>;
};

type Explanation = {
  statements: Array<{ text: string; href: string; source_type: string }>;
  recommended_action?: { text: string; href: string };
  missing: string[];
  llm_authored: boolean;
  legal_compliance_claim: boolean;
  uncertainty: string;
  verdict_authority: string;
};

function capName(item: string | { name: string; kind?: string }) {
  return typeof item === "string" ? item : item.name;
}

export default function SystemDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const [data, setData] = useState<Posture | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [explain, setExplain] = useState<Explanation | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<Posture>(`/api/v1/systems/${params.id}/posture`)
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, [params.id]);

  async function onDelete() {
    setError(null);
    try {
      await api(`/api/v1/systems/${params.id}`, { method: "DELETE" });
      router.push("/systems");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  }

  async function onExplain() {
    setBusy(true);
    setError(null);
    try {
      setExplain(await api(`/api/v1/intelligence/explain?system_id=${params.id}`));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Explain failed");
    } finally {
      setBusy(false);
    }
  }

  if (!data) {
    return error ? <ErrorBanner message={error} /> : <LoadingState />;
  }

  const item = data.system;
  const ident = data.identity || {};
  const title = ident.display_name || item.display_name || item.name;
  const identifier = ident.technical_identifier || item.technical_identifier || item.name;
  const purpose = data.profile?.purpose || item.description || "UNKNOWN";
  const posture = data.posture_summary || "NOT ASSESSED";
  return (
    <div className="stack">
      <PageHeader
        kicker="AI system profile"
        title={title}
        lede={purpose}
        crumbs={[{ href: "/systems", label: "AI systems" }, { label: title }]}
        actions={
          <button className="btn" type="button" disabled={busy} onClick={() => void onExplain()}>
            {busy ? "Explaining…" : "Explain my posture"}
          </button>
        }
      />
      <p className={`posture-banner posture-${posture.replaceAll(" ", "-").toLowerCase()}`}>
        Posture: {posture}
      </p>
      <p>
        {ident.organisation || item.organisation ? `${ident.organisation || item.organisation} · ` : ""}
        Owner {item.owner} · {item.team || "no team"} · {item.environment} ·{" "}
        <StatusPill value={item.lifecycle} /> · risk {item.risk_classification || "UNKNOWN"} ·{" "}
        {ident.origin_label || item.origin_label || "USER / MANUAL"}
        {ident.labelled_synthetic || item.labelled_synthetic ? " · labelled synthetic" : ""}
      </p>
      {identifier !== title ? <p className="muted">Technical identifier: {identifier}</p> : null}
      <p className="muted">Legal claim {String(data.legal_compliance_claim)}. UNKNOWN fields are listed. Nothing is invented.</p>
      <ErrorBanner message={error} />
      {data.missing_information.length > 0 ? (
        <section>
          <h2>Missing information</h2>
          <p className="muted">UNKNOWN fields are listed. Nothing is invented.</p>
          <ul>
            {data.missing_information.map((row) => (
              <li key={row}>{row}</li>
            ))}
          </ul>
        </section>
      ) : null}
      {explain ? (
        <section>
          <h2>Evidence-linked explanation</h2>
          <p className="muted">
            {explain.llm_authored
              ? "LLM summary of persisted facts. Verdicts stay deterministic."
              : "Deterministic explanation from persisted evidence. LLM is not used unless configured."}{" "}
            Authority {explain.verdict_authority}. Legal claim {String(explain.legal_compliance_claim)}. {explain.uncertainty}
          </p>
          <ul>
            {explain.statements.map((row) => (
              <li key={row.text}>
                {row.text} <Link href={row.href}>{row.source_type}</Link>
              </li>
            ))}
          </ul>
          {explain.recommended_action ? (
            <p>
              Next: <Link href={explain.recommended_action.href}>{explain.recommended_action.text}</Link>
            </p>
          ) : null}
        </section>
      ) : null}
      <section>
        <h2>Data, users, capabilities</h2>
        <p>
          Data: {data.data_categories.length ? data.data_categories.join(", ") : "UNKNOWN"}. Users:{" "}
          {data.users_subjects.length ? data.users_subjects.join(", ") : "UNKNOWN"}. Tools:{" "}
          {data.capabilities.length ? data.capabilities.map(capName).join(", ") : "UNKNOWN"}.
        </p>
      </section>
      <section>
        <h2>Controls</h2>
        {data.controls.length === 0 ? (
          <EmptyState title="No linked controls" detail="Controls appear here after tests, evidence, or findings are associated with this system." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Control</th>
                <th>Assurance</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              {data.controls.map((control) => (
                <tr key={control.id}>
                  <td>
                    <Link href={`/controls/${control.id}`}>{control.identifier}</Link> · {control.title}
                  </td>
                  <td>
                    <StatusPill value={control.assurance_status} tone={assuranceTone(control.assurance_status)} />
                  </td>
                  <td>
                    {control.latest_verdict ? (
                      <StatusPill value={control.latest_verdict} tone={verdictTone(control.latest_verdict)} />
                    ) : (
                      "UNKNOWN"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section>
        <h2>Threat exposure</h2>
        {data.threat_exposure.length === 0 ? (
          <EmptyState title="No mapped threats" detail="Curated techniques appear after informational mappings to this system's controls." />
        ) : (
          <ul>
            {data.threat_exposure.map((row) => (
              <li key={row.technique_key}>
                <Link href={row.href}>{row.threat_title || row.technique_title}</Link> · {row.technique_title} ·
                capability {row.affected_capability}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h2>Findings</h2>
        {data.findings.length === 0 ? (
          <EmptyState title="No findings" detail="CTRL-002 findings for this system will appear after an assurance run." />
        ) : (
          <ul>
            {data.findings.map((finding) => (
              <li key={finding.id}>
                <Link href={`/findings/${finding.id}`}>{finding.title}</Link>{" "}
                <StatusPill value={finding.verdict} tone={verdictTone(finding.verdict)} />{" "}
                <StatusPill value={finding.status} tone={findingStatusTone(finding.status)} />
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h2>Assurance tests</h2>
        {data.tests.length === 0 ? (
          <EmptyState title="No tests" detail="Confirm AUTH-01 from Assurance. Passive traces are not verdicts." />
        ) : (
          <ul>
            {data.tests.map((run) => (
              <li key={run.id}>
                {run.scenario_key} · <StatusPill value={run.verdict} tone={verdictTone(run.verdict)} /> · {run.reason_code}
                {run.parent_run_id ? " · retest" : ""}
              </li>
            ))}
          </ul>
        )}
        <p className="muted">
          Remediation: open {data.remediation_state.open}, remediated {data.remediation_state.remediated}, resolved{" "}
          {data.remediation_state.resolved}. Latest verdict {data.remediation_state.latest_verdict}.
        </p>
      </section>
      <section>
        <h2>Agent traces</h2>
        {data.traces.length === 0 ? (
          <EmptyState title="No ingested events" detail="Passive HTTP, gateway, SDK, or OTEL observations appear here. This is not a runtime firewall." />
        ) : (
          <ul>
            {data.traces.map((row) => (
              <li key={row.id}>
                {row.source_kind} · {row.tool_name || "UNKNOWN"} · authorized{" "}
                {String(row.authorization_context?.authorized ?? "UNKNOWN")}
                {row.labelled_synthetic ? " · labelled synthetic" : ""}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h2>Evidence</h2>
        {data.evidence.length === 0 ? (
          <EmptyState title="No linked evidence" detail="Hashed run envelopes and manual records linked to this system appear here." />
        ) : (
          <ul>
            {data.evidence.map((row) => (
              <li key={row.id}>
                <Link href={`/evidence/${row.id}`}>{row.title}</Link>
                {row.integrity_hash ? <span className="muted"> · {row.integrity_hash.slice(0, 12)}…</span> : null}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h2>Requirements</h2>
        {data.requirements.length === 0 ? (
          <EmptyState title="No mapped requirements" detail="Requirements appear after they are mapped to controls associated with this system." />
        ) : (
          <ul>
            {data.requirements.map((row) => (
              <li key={row.id}>
                <Link href={`/requirements/${row.id}`}>{row.title}</Link> · {row.status}
              </li>
            ))}
          </ul>
        )}
      </section>
      <details className="advanced-fold">
        <summary>Advanced</summary>
        <p className="muted">Deletion is irreversible. Prefer archive in an enterprise deployment.</p>
        <ConfirmButton
          className="btn secondary"
          label="Delete this system"
          confirmLabel="Confirm delete"
          onConfirm={() => void onDelete()}
        />
      </details>
    </div>
  );
}
