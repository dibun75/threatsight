"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";

type Detail = {
  id: string;
  title: string;
  mode: string;
  lifecycle: string;
  declaration_state: string;
  evidence_assessment: string;
  reason: string;
  known_facts: string;
  uncertain_facts: string;
  remaining_uncertainty: string;
  response_lead: string | null;
  open_actions: number;
  next_review_at: string | null;
  synthetic_label: string | null;
  is_synthetic: boolean;
  is_incident: boolean;
  services: { service_name: string; involvement: string; notes: string }[];
  roles: { role_key: string; display_name: string; is_synthetic: boolean }[];
  unfilled_roles: string[];
  critical_unfilled_roles: string[];
  actions: {
    action_id: string;
    title: string;
    status: string;
    owner: string | null;
    due_at: string | null;
    evidence_required: string;
    response_role: string;
    reopened: boolean;
  }[];
  timeline: {
    id: string;
    event_time: string;
    actor: string;
    category: string;
    summary: string;
    evidence_state: string;
    is_current: boolean;
  }[];
  decisions: {
    id: string;
    decision: string;
    rationale: string;
    decision_maker: string;
    remaining_uncertainty: string;
    effective_at: string;
  }[];
  evidence_refs: { id: string; ref_kind: string; label: string; evidence_assessment: string }[];
  not_legal_advice: string;
  closure_notes: string | null;
  lessons_learned: string | null;
};

export default function ResponseDetailPage() {
  const params = useParams<{ id: string }>();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!params?.id) return;
    api<Detail>(`/api/v1/response/${params.id}`)
      .then(setDetail)
      .catch(() => setError("Response workspace could not be loaded."));
  }, [params?.id]);

  if (error) {
    return (
      <article className="stack">
        <h1>Response</h1>
        <p role="alert">{error}</p>
      </article>
    );
  }
  if (!detail) {
    return (
      <article className="stack">
        <h1>Response</h1>
        <p className="skeleton" aria-busy="true">
          Loading response workspace.
        </p>
      </article>
    );
  }

  const exercise = detail.is_synthetic || detail.mode === "exercise";
  const next =
    detail.lifecycle === "closed"
      ? "Closed — reopen only with administrator authorization."
      : detail.open_actions > 0
        ? "Complete open verification actions and review uncertainty."
        : "Review decisions and evidence freshness.";

  return (
    <article className="stack response-detail">
      <p>
        <Link href="/response">Response</Link>
      </p>
      <h1>{detail.title}</h1>
      {exercise ? (
        <p>
          <strong>Synthetic exercise</strong> — not a confirmed incident.
        </p>
      ) : null}

      <section aria-label="Situation">
        <h2>Situation</h2>
        <p>
          <strong>What are we assessing?</strong> {detail.reason}
        </p>
        <p>
          <strong>Is an incident declared?</strong>{" "}
          {detail.is_incident
            ? "Yes — confirmed_incident"
            : `${detail.declaration_state}${exercise ? " (exercise — not an incident)" : ""}`}
        </p>
        <p>
          <strong>Which services may be involved?</strong>{" "}
          {detail.services.map((s) => s.service_name).join(", ") || "None listed"}
        </p>
        <p>
          <strong>What is known?</strong> {detail.known_facts || "Not recorded"}
        </p>
        <p>
          <strong>What is uncertain?</strong> {detail.uncertain_facts || "Not recorded"}
        </p>
        <p>
          <strong>Who leads?</strong> {detail.response_lead || "Response lead unfilled"}
          {detail.roles.length > 1 ? ` · ${detail.roles.length} role assignments (one person may hold multiple roles)` : ""}
        </p>
        <p>
          <strong>What happens next?</strong> {next}
        </p>
        <p>
          Mode: {detail.mode} · Lifecycle: {detail.lifecycle} · Evidence: {detail.evidence_assessment}
          {detail.next_review_at ? ` · Next review: ${detail.next_review_at}` : ""}
        </p>
      </section>

      <section aria-label="Services">
        <h2>Services</h2>
        <ul>
          {detail.services.map((s) => (
            <li key={s.service_name}>
              {s.service_name} — {s.involvement}
              {s.notes ? `: ${s.notes}` : ""}
            </li>
          ))}
        </ul>
      </section>

      <section aria-label="Actions">
        <h2>Actions</h2>
        <ul>
          {detail.actions.map((a) => (
            <li key={a.action_id}>
              <Link href={`/actions/${a.action_id}`}>{a.title}</Link> — {a.status}
              {a.owner ? ` · ${a.owner}` : " · Unassigned"}
              {a.due_at ? ` · due ${a.due_at}` : ""}
              {a.response_role ? ` · role ${a.response_role}` : ""}
              {a.reopened ? " · reopened" : ""}
              <br />
              Evidence required: {a.evidence_required}
            </li>
          ))}
          {!detail.actions.length ? <li>No linked readiness actions.</li> : null}
        </ul>
      </section>

      <section aria-label="Evidence">
        <h2>Evidence</h2>
        <ul>
          {detail.evidence_refs.map((e) => (
            <li key={e.id}>
              {e.label || e.ref_kind} — assessment: {e.evidence_assessment}
            </li>
          ))}
          {!detail.evidence_refs.length ? <li>No pinned evidence references.</li> : null}
        </ul>
      </section>

      <section aria-label="Timeline">
        <h2>Timeline</h2>
        <ol>
          {detail.timeline.map((t) => (
            <li key={t.id}>
              <time dateTime={t.event_time}>{t.event_time}</time> · {t.category} · {t.actor}: {t.summary}
              {!t.is_current ? " (superseded)" : ""}
            </li>
          ))}
        </ol>
      </section>

      <section aria-label="Decisions">
        <h2>Decisions</h2>
        <ul>
          {detail.decisions.map((d) => (
            <li key={d.id}>
              <strong>{d.decision}</strong> — {d.rationale}
              <br />
              Maker: {d.decision_maker} · Uncertainty: {d.remaining_uncertainty || "None recorded"}
            </li>
          ))}
        </ul>
      </section>

      <section aria-label="Reports">
        <h2>Reports</h2>
        <p>
          Situation reports are versioned and printable from the API. Finalized reports may be included in signed
          response snapshots. Signature proves integrity only.
        </p>
        <p>
          <Link className="btn secondary" href={`/response/${detail.id}/print`}>
            Printable situation view
          </Link>
        </p>
      </section>

      <section aria-label="Communications">
        <h2>Communications</h2>
        <p>Draft — not sent. No email, Teams, Slack, SMS, Jira, or ServiceNow delivery from ThreatSight.</p>
      </section>

      <section aria-label="Regulatory preparation">
        <h2>Regulatory preparation</h2>
        <p>{detail.not_legal_advice}</p>
        <p>Applicability and reporting obligation default to not determined until a liaison confirms.</p>
      </section>

      <section aria-label="Roles">
        <h2>Roles</h2>
        <ul>
          {detail.roles.map((r) => (
            <li key={`${r.role_key}-${r.display_name}`}>
              {r.role_key}: {r.display_name}
              {r.is_synthetic ? " (synthetic)" : ""}
            </li>
          ))}
        </ul>
        {detail.unfilled_roles.length ? <p>Unfilled: {detail.unfilled_roles.join(", ")}</p> : null}
        {detail.critical_unfilled_roles.length ? (
          <p>Critical unfilled: {detail.critical_unfilled_roles.join(", ")}</p>
        ) : null}
      </section>

      {detail.closure_notes ? (
        <section aria-label="Closure">
          <h2>Closure</h2>
          <p>{detail.closure_notes}</p>
          {detail.lessons_learned ? <p>Lessons: {detail.lessons_learned}</p> : null}
        </section>
      ) : null}
    </article>
  );
}
