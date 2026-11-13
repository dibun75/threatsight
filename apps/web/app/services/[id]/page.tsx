"use client";

import Link from "next/link";
import { useParams, usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";

import { SourceTime } from "@/components/command/SourceTime";
import { api } from "@/lib/api";
import { presentation } from "@/lib/experience";
import { primaryAction } from "@/lib/telemetry-state";
import { scrubReferenceText } from "@/lib/reference-names";
import { commercialTitle, maturityStatement, presentedValue } from "@/lib/vocabulary";

type Step = { from: string; relationship: string; to: string; evidence_state: string; source: string; freshness: string; limitation: string };
type Asset = { node_id: string; label: string; node_type: string; relationship: string; role: string; evidence_state: string; maturity: string; freshness: string; source: string; collected_at: string | null; confidence: string };
type Threat = { match_id: string; advisory_id: string | null; title: string; cve: string; classification: string; maturity: string; freshness: string; relationship: string; source: string; collected_at: string; asset_node_id: string | null; kev_listed: boolean | null; epss_score: number | null; epss_date: string | null; review_state: string; limitations: string[] };
type PathItem = { id: string; state: string; evidence_state: string; freshness: string; maturity: string; source: string; explanation: string; steps: Step[]; limitations: string[] };
type Control = { id: string; title: string; objective: string; relevance: string; expected_protection: string; latest_evidence: string; evidence_source: string; evidence_status: string; verification_maturity: string; gaps: string[]; next_step: string };
type Investigation = {
  name: string;
  purpose: string;
  maturity: string;
  data_context: string;
  decision_state: string;
  explanation: string;
  recommended_step: string;
  consequence?: string | null;
  owner_state: string;
  deadline_state: string;
  evidence_completeness: string;
  last_relevant_update: string | null;
  comparison: string;
  score: null;
  threats: Threat[];
  assets: Asset[];
  paths: PathItem[];
  controls: Control[];
  actions: { title: string; evidence_required: string; owner_state: string; deadline_state: string }[];
  limitations: string[];
  provenance: { snapshot_id: string; snapshot_completed_at: string | null; correlation_run_id: string | null; analysis_run_id: string | null };
};

const SECTIONS = ["situation", "technology", "paths", "controls", "actions", "evidence"] as const;
const TAB_ALIAS: Record<string, (typeof SECTIONS)[number]> = {
  threats: "technology",
  assets: "technology",
  provenance: "evidence",
};

function requestedTab(search: { get: (key: string) => string | null }): (typeof SECTIONS)[number] {
  const value = search.get("tab") || search.get("section") || "";
  if (SECTIONS.includes(value as (typeof SECTIONS)[number])) return value as (typeof SECTIONS)[number];
  return TAB_ALIAS[value] ?? "situation";
}

function EvidenceIntegrity({ actionId }: { actionId: string }) {
  const [info, setInfo] = useState<{
    id?: string;
    label?: string;
    status?: string;
    state?: string;
    fingerprint?: string;
    signed_at?: string;
    proves?: string;
    does_not_prove?: string;
    action_status?: string;
  } | null>(null);
  const [note, setNote] = useState("");
  function load() {
    return api<{
      id?: string;
      label?: string;
      status?: string;
      state?: string;
      fingerprint?: string;
      signed_at?: string;
      proves?: string;
      does_not_prove?: string;
      action_status?: string;
    }>(`/api/v1/evidence/signing/actions/${actionId}/signature`)
      .then(setInfo)
      .catch(() => setInfo({ status: "unsigned", label: "Unsigned" }));
  }
  useEffect(() => {
    void load();
  }, [actionId]);
  async function verifyAgain() {
    if (!info?.id) return;
    setNote("");
    try {
      const result = await api<{ state?: string }>(`/api/v1/evidence/signing/signatures/${info.id}/verify`, { method: "POST", body: "{}" });
      setNote(`Verification ${result.state ?? "complete"}.`);
      await load();
    } catch (err) {
      setNote(err instanceof Error ? err.message : "Verification failed.");
    }
  }
  async function downloadBundle() {
    if (!info?.id) return;
    setNote("");
    try {
      const body = await api<{ filename?: string; bundle?: unknown }>(`/api/v1/evidence/signing/signatures/${info.id}/bundle`, {
        method: "POST",
        body: "{}",
      });
      const blob = new Blob([JSON.stringify(body.bundle ?? body, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = body.filename ?? `evidence-verification-${info.id}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      setNote("Verification bundle downloaded. Offline verification does not need the private key.");
    } catch (err) {
      setNote(err instanceof Error ? err.message : "Bundle download failed.");
    }
  }
  if (!info) return <p className="skeleton" aria-busy="true">Loading evidence integrity.</p>;
  const label = info.label ?? (info.status === "unsigned" ? "Unsigned" : "Reference-signed evidence");
  const closure = info.action_status === "reopened" ? "Superseded closure." : info.action_status === "closed" ? "Current closure." : "";
  return (
    <section aria-label="Evidence integrity">
      <h4>Evidence integrity</h4>
      <p>{label}. {info.state ? `Verification ${info.state}.` : ""} {closure} {info.fingerprint ? `Key fingerprint ${info.fingerprint}.` : ""} {info.signed_at ? `Signed ${info.signed_at}.` : ""}</p>
      <p>{info.proves ?? "An integrity digest is not a digital signature until a deployment signature exists."}</p>
      <p>{info.does_not_prove ?? "A deployment signature is not auditor approval, certification, or proof that a control works."}</p>
      {info.id ? (
        <p className="no-print">
          <button className="btn" type="button" onClick={() => void downloadBundle()}>Download verification bundle</button>{" "}
          <button className="btn" type="button" onClick={() => void verifyAgain()}>Verify again</button>
        </p>
      ) : null}
      {note ? <p role="status">{note}</p> : null}
    </section>
  );
}

function AccountableActions({ serviceId }: { serviceId: string }) {
  const [rows, setRows] = useState<{ id: string; title: string; status: string; owner_subject: string | null; due_state: string | null; requirements_pending: number; manifest_digest?: string | null; closure_outcome: string | null }[]>([]);
  useEffect(() => {
    api<{ items: { id: string; title: string; status: string; owner_subject: string | null; due_state: string | null; requirements_pending: number; service_node_id: string | null; closure_outcome: string | null; manifest_digest?: string | null }[] }>("/api/v1/readiness/actions")
      .then((body) => setRows((body.items ?? []).filter((row) => row.service_node_id === serviceId)))
      .catch(() => setRows([]));
  }, [serviceId]);
  if (rows.length === 0) return <p>No accountable readiness action is stored for this service.</p>;
  return (
    <section aria-label="Accountable readiness actions">
      <h3>Accountable readiness actions</h3>
      {rows.map((row) => (
        <article className="service-card" key={row.id}>
          <h4>{row.title}</h4>
          <p>Status {row.status}. Owner {row.owner_subject ?? "Unassigned"}. Due {row.due_state ?? "not set"}. Pending requirements {row.requirements_pending}. Closure outcome {row.closure_outcome ?? "not closed"}.</p>
          <p>Manifest digest {row.manifest_digest ?? "not stored"}.</p>
          <EvidenceIntegrity actionId={row.id} />
          <p>Synthetic reference. A closed action is not proof that related risk no longer exists. An evidence manifest is an integrity digest, not a signature, until a deployment signature is attached.</p>
          <p><Link href={`/actions?service=${serviceId}&status=${row.status}`}>Open filtered actions</Link></p>
        </article>
      ))}
    </section>
  );
}

function InvestigationPage() {
  const params = useParams<{ id: string }>();
  const search = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const section = requestedTab(search);
  const audience = search.get("audience") === "technical" ? "technical" : "executive";
  const [item, setItem] = useState<Investigation | null>(null);
  const [error, setError] = useState("");
  type ReadinessRow = {
    id: string;
    service_node_id: string | null;
    control: string;
    check_title: string;
    state: string;
    approval_required: boolean;
    rationale: string;
    request_id: string | null;
    request_status: string | null;
    result_outcome: string | null;
    result_summary: string | null;
    result_freshness: string | null;
    evidence_hash: string | null;
    decision_outcome: string | null;
    next_decision: string;
    limitations: string[];
  };
  const [readiness, setReadiness] = useState<ReadinessRow[]>([]);
  const [readinessNote, setReadinessNote] = useState("");
  function openTab(value: (typeof SECTIONS)[number]) {
    const next = new URLSearchParams(search.toString());
    next.set("tab", value);
    next.delete("section");
    router.push(`${pathname}?${next.toString()}`, { scroll: false });
  }
  function loadReadiness() {
    return api<{ recommendations: ReadinessRow[] }>("/api/v1/readiness/summary")
      .then((body) => setReadiness((body.recommendations ?? []).filter((row) => row.service_node_id === params.id)))
      .catch(() => setReadiness([]));
  }
  useEffect(() => {
    api<Investigation>(`/api/v1/investigations/services/${params.id}`).then(setItem).catch(() => setError("This service investigation is not available."));
    void loadReadiness();
  }, [params.id]);
  async function previewAndApprove(recommendationId: string) {
    setReadinessNote("");
    try {
      await api(`/api/v1/readiness/recommendations/${recommendationId}/preview`, { method: "POST", body: "{}" });
      const request = await api<{ id: string; status: string; result?: { outcome: string; summary: string } }>(`/api/v1/readiness/recommendations/${recommendationId}/approve`, { method: "POST", body: "{}" });
      setReadinessNote(`Approved. Execution state: ${request.status}. ${request.result?.summary ?? "Result pending human decision."}`);
      await loadReadiness();
    } catch (err) {
      setReadinessNote(err instanceof Error ? err.message : "Approval failed.");
    }
  }
  async function recordDecision(requestId: string) {
    setReadinessNote("");
    try {
      const decision = await api<{ outcome: string }>(`/api/v1/readiness/requests/${requestId}/decisions`, {
        method: "POST",
        body: JSON.stringify({ outcome: "accepted", rationale: "Reference verification accepted. This is not compliance certification or proof that a control works." }),
      });
      setReadinessNote(`Human decision recorded: ${decision.outcome}. Next action remains accountable to the assigned owner.`);
      await loadReadiness();
    } catch (err) {
      setReadinessNote(err instanceof Error ? err.message : "Decision failed.");
    }
  }
  if (error) return <p role="alert">{error}</p>;
  if (!item) return <p className="skeleton" aria-busy="true">Loading the service investigation.</p>;
  return (
    <article className="stack command-center">
      <p><Link href="/demo">Command center</Link> · <Link href="/services">Services</Link></p>
      <p className="kicker">{item.data_context} · {item.maturity}</p>
      <h1>{item.name}</h1>
      <p className="state-badge synthetic">{presentation(item.decision_state)}</p>
      <p>{scrubReferenceText(item.explanation)}</p>
      <section className="decision-card" aria-label="Decision">
        <h2>Required decision</h2>
        <p>{primaryAction(audience === "executive" ? item.recommended_step : item.purpose)}</p>
        <p>Evidence completeness: {item.evidence_completeness}</p>
        <p>Last relevant update: {item.last_relevant_update ? <SourceTime value={item.last_relevant_update} /> : "Not recorded"}. {item.comparison}</p>
        <p>Owner: {item.owner_state === "not_assigned" ? "Unassigned" : item.owner_state}. Deadline: {item.deadline_state === "not_recorded" ? "Not recorded" : item.deadline_state}.</p>
        <p>{item.consequence ?? "Business consequence is not recorded."}</p>
      </section>
      <div className="metric-switch" role="tablist" aria-label="Investigation">
        {SECTIONS.map((value) => (
          <button key={value} className="btn secondary" type="button" role="tab" aria-selected={section === value} onClick={() => openTab(value)}>{value === "technology" ? "Technology" : value[0].toUpperCase() + value.slice(1)}</button>
        ))}
      </div>
      {section === "situation" ? (
        <section>
          <h2>Why this service is shown</h2>
          <p>{scrubReferenceText(item.explanation)}</p>
          <p>Next decision: {primaryAction(item.recommended_step)}. Owner: {item.owner_state === "not_assigned" ? "Unassigned" : item.owner_state}.</p>
          <p>Evidence that closes it: {item.actions[0]?.evidence_required ?? "Installed product version and an assigned owner."}</p>
          <p>There is no combined score.</p>
        </section>
      ) : null}
      {section === "technology" ? (
        <section>
          {item.threats.length === 0 ? <p className="empty-state">No stored match names this service. That is unknown, not proof of safety.</p> : null}
          {item.threats.map((threat) => (
            <article className="service-card" key={threat.match_id}>
              <h2>{commercialTitle(threat.title)}</h2>
              <p>Synthetic reference. {presentedValue(threat.classification)}. {maturityStatement(threat.maturity)} {presentedValue(threat.freshness)}. {presentedValue(threat.relationship)}.</p>
              <p>{presentedValue(threat.source)}. Collected {threat.collected_at}. KEV {threat.kev_listed === null ? "not recorded" : threat.kev_listed ? "listed" : "not listed"}. EPSS {threat.epss_score ?? "not recorded"} {threat.epss_date ?? ""}.</p>
              <p>Review {threat.review_state}.</p>
              <details><summary>Technical details</summary><p>Stored maturity {threat.maturity}. Stored source {threat.source}. {threat.limitations.join(", ")}</p></details>
              <p>
                <Link href={`/exposure/matches/${threat.match_id}`}>Open the match</Link>
                {threat.advisory_id ? <> · <Link href={`/threats/advisories/${threat.advisory_id}`}>View source advisory</Link></> : " · Source advisory is not recorded."}
                {threat.asset_node_id ? <> · <Link href={`/exposure/assets/${threat.asset_node_id}`}>Open the asset</Link></> : " · Asset record is not in this membership."}
              </p>
            </article>
          ))}
        </section>
      ) : null}
      {section === "technology" && item.assets ? (
        <div className="table-scroll" tabIndex={0}>
          <table>
            <caption>Assets and technologies stored as service members.</caption>
            <thead><tr><th scope="col">Record</th><th scope="col">Relationship</th><th scope="col">Evidence</th><th scope="col">Source</th><th scope="col">Collected</th></tr></thead>
            <tbody>
              {item.assets.map((asset) => (
                <tr key={asset.node_id}>
                  <th scope="row"><Link href={`/exposure/assets/${asset.node_id}`}>{scrubReferenceText(asset.label)}</Link></th>
                  <td>{asset.relationship}. {asset.role}</td>
                  <td>{presentedValue(asset.evidence_state)}. {presentedValue(asset.maturity)}. {presentedValue(asset.freshness)}. {presentedValue(asset.confidence)}</td>
                  <td>{presentedValue(asset.source)}</td>
                  <td>{asset.collected_at ?? "Not recorded"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {section === "paths" ? (
        <section>
          {item.paths.length === 0 ? <p className="empty-state">No candidate path is stored for this service. That is unknown, not proof that no path exists.</p> : null}
          {item.paths.map((path) => (
            <article className="service-card" key={path.id}>
              <h2>{presentedValue(path.evidence_state)}</h2>
              <p>{scrubReferenceText(path.explanation)}</p>
              <p>Source {presentedValue(path.source)}. Freshness {presentedValue(path.freshness)}. Maturity {maturityStatement(path.maturity)}</p>
              <ol>
                {path.steps.map((step, index) => <li key={`${path.id}-${index}`}>{scrubReferenceText(step.from)} — {presentedValue(step.relationship)} — {scrubReferenceText(step.to)}. {presentedValue(step.evidence_state)}. {scrubReferenceText(step.limitation)}</li>)}
              </ol>
              <p><Link href={`/exposure/paths/${path.id}`}>Open the path</Link></p>
            </article>
          ))}
        </section>
      ) : null}
      {section === "controls" ? (
        <section>
          {item.controls.length === 0 ? <p className="empty-state">No assurance control is linked to this service. A missing link is unknown, not proof that no control exists. Configuration is not effectiveness.</p> : null}
          {item.controls.map((control) => (
            <article className="service-card" key={control.id}>
              <h2><Link href={`/exposure/assets/${control.id}`}>{control.title}</Link></h2>
              <p>{control.objective}</p>
              <p>Why it is here: {control.relevance}</p>
              <p>Synthetic reference. Expected protection: {control.expected_protection}. Latest evidence: {control.latest_evidence === "gap" ? "Configured, not observed" : presentedValue(control.latest_evidence)}. Source {presentedValue(control.evidence_source)}. Status {control.evidence_status === "gap" ? "Configured, not observed" : presentedValue(control.evidence_status)}. Maturity {presentedValue(control.verification_maturity)}.</p>
              <p>Gaps: {control.gaps.map((gap) => presentedValue(gap)).join(", ") || "None recorded"}.</p>
              <p>Next verification: {control.next_step}</p>
            </article>
          ))}
          <section aria-label="Verification recommendation">
            <h2>Verification recommendation</h2>
            {readiness.length === 0 ? <p>No verification recommendation is stored for this service.</p> : readiness.map((row) => (
              <article className="service-card" key={row.id}>
                <h3>{row.control}</h3>
                <p>{row.rationale}</p>
                <p>Exact check: {row.check_title}. Maturity: Validated with reference data. Approval state: {row.state}. Execution state: {row.request_status ?? "not started"}. Latest result: {row.result_outcome ? presentedValue(row.result_outcome) : "Not recorded"}. Evidence freshness: {row.result_freshness ? presentedValue(row.result_freshness) : "unknown until a result is recorded"}. Owner: Unassigned. Next decision: {row.next_decision}</p>
                {row.result_summary ? <p>{row.result_summary}</p> : null}
                {row.evidence_hash ? <p>Evidence hash: {row.evidence_hash}. Limitations: {(row.limitations ?? []).map((item) => presentedValue(item)).join(", ") || "None recorded"}.</p> : null}
                {row.decision_outcome ? <p>Human decision: {presentedValue(row.decision_outcome)}.</p> : null}
                {row.approval_required ? <p><button className="btn" type="button" onClick={() => void previewAndApprove(row.id)}>Preview and approve reference verification</button></p> : null}
                {row.request_id && row.request_status === "succeeded" && !row.decision_outcome ? (
                  <p><button className="btn" type="button" onClick={() => void recordDecision(row.request_id!)}>Record human decision: accepted</button></p>
                ) : null}
                {readinessNote ? <p role="status">{readinessNote}</p> : null}
                <p>A recommendation is not a control failure. Reference execution does not contact a customer device and does not change infrastructure.</p>
              </article>
            ))}
          </section>
        </section>
      ) : null}
      {section === "actions" ? (
        <section>
          <h2>{item.actions[0]?.title ?? "No recorded action"}</h2>
          <p>{item.recommended_step}</p>
          <p>Owner: {item.owner_state === "not_assigned" ? "Unassigned" : item.owner_state}. Deadline: {item.deadline_state === "not_recorded" ? "Not recorded" : item.deadline_state}.</p>
          <p>Opening this page does not create an action. Assignment stays with a platform administrator.</p>
          <p>Evidence required: {item.actions[0]?.evidence_required ?? "Not recorded."}</p>
          <AccountableActions serviceId={params.id} />
          <p><Link href={`/actions?service=${params.id}${item.threats[0]?.match_id ? `&match=${item.threats[0].match_id}` : ""}${item.threats[0]?.advisory_id ? `&advisory=${item.threats[0].advisory_id}` : ""}`}>Open the action register</Link></p>
        </section>
      ) : null}
      {section === "evidence" ? (
        <details className="disclosure" open>
          <summary>Provenance and limitations</summary>
          <p>Snapshot {item.provenance.snapshot_id}. Completed {item.provenance.snapshot_completed_at ?? "not recorded"}.</p>
          <p>Correlation run {item.provenance.correlation_run_id ?? "not recorded"}. Analysis run {item.provenance.analysis_run_id ?? "not recorded"}.</p>
          <ul>{item.limitations.map((limit) => <li key={limit}>{presentedValue(limit)}</li>)}</ul>
        </details>
      ) : null}
    </article>
  );
}

export default function Page() {
  return <Suspense fallback={<p className="skeleton">Loading the service investigation.</p>}><InvestigationPage /></Suspense>;
}
