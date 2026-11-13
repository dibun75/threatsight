"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { TelemetryBanner, useActivity } from "@/components/command/TelemetryBanner";
import { api } from "@/lib/api";
import { primaryAction } from "@/lib/telemetry-state";

type Decision = {
  service_id: string;
  name: string;
  state: string;
  explanation: string;
  live_count: number;
  reference_count: number;
  path_count: number;
  control_gap: string;
  required_decision?: string;
  owner_state?: string;
  recommended_step: string;
};

type Summary = { services: Decision[] };
type Readiness = { recommendations: { id: string; service: string; control: string; rationale: string; approval_required: boolean; state: string }[] };
type ActionSummary = { unassigned: number; overdue: number; awaiting_evidence: number; ready_for_review: number; reopened: number };
type IntegrityRow = {
  title: string;
  status: string;
  label?: string;
  state?: string;
  fingerprint?: string;
  signed_at?: string;
};

export default function BriefingPage() {
  const { activity, state } = useActivity();
  const [body, setBody] = useState<Summary | null>(null);
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [actions, setActions] = useState<ActionSummary | null>(null);
  const [integrity, setIntegrity] = useState<IntegrityRow[]>([]);
  const [detailOpen, setDetailOpen] = useState(false);
  type ResponseBrief = {
    assessments_active: number;
    exercises_active: number;
    confirmed_incidents: number;
    note: string;
  };
  const [responseBrief, setResponseBrief] = useState<ResponseBrief | null>(null);
  useEffect(() => {
    api<Summary>("/api/v1/decisions/services").then(setBody).catch(() => setBody({ services: [] }));
    api<Readiness>("/api/v1/readiness/summary").then(setReadiness).catch(() => setReadiness(null));
    api<ActionSummary>("/api/v1/readiness/actions/summary").then(setActions).catch(() => setActions(null));
    api<ResponseBrief>("/api/v1/response/summary").then(setResponseBrief).catch(() => setResponseBrief(null));
    api<{ items: { id: string; title: string; status: string; manifest_digest?: string | null }[] }>("/api/v1/readiness/actions")
      .then(async (body) => {
        const rows = (body.items ?? []).filter((row) => row.manifest_digest).slice(0, 5);
        const details = await Promise.all(
          rows.map(async (row) => {
            try {
              const sig = await api<{ label?: string; state?: string; fingerprint?: string; signed_at?: string }>(
                `/api/v1/evidence/signing/actions/${row.id}/signature`,
              );
              return {
                title: row.title,
                status: row.status,
                label: sig.label,
                state: sig.state,
                fingerprint: sig.fingerprint,
                signed_at: sig.signed_at,
              };
            } catch {
              return { title: row.title, status: row.status, label: "Unsigned" };
            }
          }),
        );
        setIntegrity(details);
      })
      .catch(() => setIntegrity([]));
  }, []);
  const services = body?.services ?? [];
  const owner = (item: Decision) => (item.owner_state === "not_assigned" || !item.owner_state ? "Unassigned" : item.owner_state);
  return (
    <article className="stack briefing">
      <h1>Executive briefing</h1>
      <p className="no-print">
        <button className="btn" type="button" onClick={() => { setDetailOpen(true); window.setTimeout(() => window.print(), 0); }}>Print briefing</button>
        {" "}
        <Link href="/demo">Open the command center</Link>
      </p>
      <section aria-label="Current decision">
        <h2>Current decision</h2>
        {services.length === 0 ? <p>Loading the service decisions.</p> : services.map((item) => (
          <p key={item.service_id}>
            <Link href={`/services/${item.service_id}?tab=situation`}>{item.name}</Link>
            {": "}
            {item.required_decision || primaryAction(item.recommended_step)}
            {" "}Control: {item.control_gap} Owner: {owner(item)}.
          </p>
        ))}
      </section>
      <section className="briefing-summary" aria-label="Executive summary">
        <h2>Decision summary</h2>
        <p><strong>{services.length}</strong> services need a decision · <strong>{actions?.unassigned ?? "—"}</strong> unassigned actions · <strong>{responseBrief?.confirmed_incidents ?? "—"}</strong> confirmed incidents.</p>
        <p><strong>Known:</strong> candidate evidence is recorded. <strong>Uncertain:</strong> versions, reachability, effective privilege, and ownership.</p>
      </section>
      <details className="briefing-detail" open={detailOpen} onToggle={(event) => setDetailOpen(event.currentTarget.open)}>
        <summary>Evidence and operational detail</summary>
        {detailOpen ? <>
      <section aria-label="Evidence integrity">
        <h2>Evidence integrity</h2>
        {integrity.length === 0 ? (
          <p>No closure evidence manifest is stored for this briefing.</p>
        ) : (
          integrity.map((row) => (
            <p key={row.title}>
              {row.title}: {row.label ?? "Unsigned"}
              {row.state ? `. Verification ${row.state}` : ""}
              {row.status === "reopened" ? ". Superseded closure." : row.status === "closed" ? ". Current closure." : `. Action ${row.status}.`}
              {row.fingerprint ? ` Key fingerprint ${row.fingerprint}.` : ""}
              {row.signed_at ? ` Signed ${row.signed_at}.` : ""}
              {" "}A deployment signature is not auditor approval, certification, or proof that a control works.
            </p>
          ))
        )}
      </section>
      <section>
        <h2>What is known</h2>
        <p>Global observations are stored separately from these synthetic services. Technology matches remain candidates.</p>
      </section>
      <section>
        <h2>What remains uncertain</h2>
        <p>Installed versions, effective privilege, observed reachability, and ownership.</p>
      </section>
      <section aria-label="Readiness verification required">
        <h2>Readiness verification required</h2>
        {(readiness?.recommendations ?? []).length === 0 ? (
          <p>No verification recommendation is stored.</p>
        ) : (
          readiness?.recommendations.slice(0, 3).map((item) => (
            <p key={item.id}>
              {item.service}: {item.control}. Current evidence state: Configured, not observed. {item.approval_required ? "Approval required." : `State: ${item.state}.`} Owner: Unassigned. Required decision: review the defined check result.
            </p>
          ))
        )}
      </section>
      <section aria-label="Accountable actions">
        <h2>Accountable actions</h2>
        {actions ? (
          <p>
            Actions without owners: {actions.unassigned}. Overdue: {actions.overdue}. Awaiting evidence: {actions.awaiting_evidence}. Ready for review: {actions.ready_for_review}. Reopened: {actions.reopened}.
            Closure does not prove security or compliance.
          </p>
        ) : (
          <p>No accountability summary is stored.</p>
        )}
      </section>
      <section aria-label="Response coordination">
        <h2>Response coordination</h2>
        {responseBrief ? (
          <p>
            Operational assessments active: {responseBrief.assessments_active}. Synthetic exercises active:{" "}
            {responseBrief.exercises_active} (not incidents). Confirmed incidents: {responseBrief.confirmed_incidents}.{" "}
            {responseBrief.note} <Link href="/response">Open response</Link>.
          </p>
        ) : (
          <p>No response summary is stored.</p>
        )}
      </section>
        </>
        : null}
      </details>
      <p>
        Source freshness: {activity?.windows?.["24h"]?.source_updated_at ?? activity?.primary?.source_updated_at ?? "Loading global activity."}
        {" "}Live global observations are not customer traffic.
      </p>
      <section className="briefing-later">
        <h2>What changed externally</h2>
        <TelemetryBanner state={state} activity={activity} />
        <details>
          <summary>How to interpret this</summary>
          <p>Matches are candidates. Paths are not packet delivery. A configured control is not an observed control. A printout is not a signed report.</p>
        </details>
      </section>
    </article>
  );
}