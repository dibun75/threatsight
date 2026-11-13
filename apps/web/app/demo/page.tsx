"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { ThreatObservatory } from "@/components/command/ThreatObservatory";
import { api } from "@/lib/api";
import { primaryAction } from "@/lib/telemetry-state";
import { matchLabel, maturityStatement } from "@/lib/vocabulary";

type Decision = {
  service_id: string;
  name: string;
  state: string;
  explanation: string;
  live_count: number;
  reference_count: number;
  path_count: number;
  control_gap?: string;
  recommended_step: string;
  synthetic?: boolean;
};

type Threat = { match_id: string; advisory_id: string | null; title: string; classification: string; maturity: string };
type Journey = {
  consequence?: string | null;
  recommended_step?: string;
  owner_state?: string;
  controls?: { latest_evidence?: string; title?: string }[];
  threats?: Threat[];
  paths?: { id: string; evidence_state: string }[];
};

export default function DemoPage() {
  const [services, setServices] = useState<Decision[]>([]);
  const [journey, setJourney] = useState<Journey | null>(null);
  type ReadinessSummary = {
    services_needing_verification: number;
    recommendations: { id: string; service: string; service_node_id: string | null; control: string; state: string; rationale: string; approval_required: boolean; check_title: string }[];
  };
  const [readiness, setReadiness] = useState<ReadinessSummary | null>(null);
  type ActionSummary = { unassigned: number; due_soon: number; overdue: number; awaiting_evidence: number; ready_for_review: number; reopened: number };
  const [actions, setActions] = useState<ActionSummary | null>(null);
  const [pending, setPending] = useState(true);
  const [detailOpen, setDetailOpen] = useState(false);
  const [servicesOpen, setServicesOpen] = useState(false);
  const [error, setError] = useState("");
  type EmergingItem = { cluster_id: string; cve: string | null; title: string; exploitation_state: string; organization_relevance: string; required_action: string };
  const [emerging, setEmerging] = useState<EmergingItem[]>([]);
  type ResponseSummary = {
    assessments_active: number;
    exercises_active: number;
    confirmed_incidents: number;
    decisions_overdue: number;
    unfilled_critical_roles: number;
    note: string;
  };
  const [responseSummary, setResponseSummary] = useState<ResponseSummary | null>(null);
  useEffect(() => {
    api<{ services: Decision[] }>("/api/v1/decisions/services")
      .then((body) => {
        const rows = body.services ?? [];
        setServices(rows);
        const first = rows[0];
        return Promise.all([
          first ? api<Journey>(`/api/v1/investigations/services/${first.service_id}`).then(setJourney) : Promise.resolve(),
          api<ReadinessSummary>("/api/v1/readiness/summary").then(setReadiness).catch(() => setReadiness(null)),
          api<ActionSummary>("/api/v1/readiness/actions/summary").then(setActions).catch(() => setActions(null)),
          api<{ items: EmergingItem[] }>("/api/v1/multisource/command-center").then((page) => setEmerging(page.items)).catch(() => setEmerging([])),
          api<ResponseSummary>("/api/v1/response/summary").then(setResponseSummary).catch(() => setResponseSummary(null)),
        ]);
      })
      .catch(() => setError("The command center could not be loaded."))
      .finally(() => setPending(false));
  }, []);
  const lead = services[0] ?? null;
  const threat = journey?.threats?.[0];
  const path = journey?.paths?.[0];
  const action = primaryAction(journey?.recommended_step || lead?.recommended_step);
  const owner = journey?.owner_state === "not_assigned" || !journey?.owner_state ? "Unassigned" : journey.owner_state;
  const reviewCount = services.filter((item) => item.state !== "verified_current").length;
  const unassigned = services.filter((item) => item.state === "action_required" || item.state === "investigation_required" || item.state === "evidence_stale").length;
  const actionHref = lead
    ? `/actions?service=${lead.service_id}${threat?.match_id ? `&match=${threat.match_id}` : ""}${threat?.advisory_id ? `&advisory=${threat.advisory_id}` : ""}`
    : "/actions";
  return (
    <article className="stack command-center">
      <h1 className="sr-only">Command center</h1>
      {error ? <p role="alert">{error}</p> : null}
      <section className="decision-card decision-strip" aria-label="Decision summary">
        <h2>{pending ? "Loading" : lead ? `${lead.name} needs review` : "No service needs review"}</h2>
        <p>{pending ? "" : `${reviewCount} to review · ${unassigned} need an owner`}</p>
        <p>
          <Link className="btn" href={lead ? `/services/${lead.service_id}?tab=situation` : "/services"}>Review</Link>
          {" "}
          <Link href="/briefing">Briefing</Link>
        </p>
      </section>
      <ThreatObservatory />
      <details className="command-detail" onToggle={(event) => setDetailOpen(event.currentTarget.open)}>
        <summary>Operational detail</summary>
        <>{detailOpen ? <div className="command-detail-body">
      <section aria-label="Decision chain">
        <h2>Decision chain</h2>
        {pending ? <p className="skeleton" aria-busy="true">Loading the next action.</p> : (
          <ol className="decision-chain">
            <li><span>Global observations</span><strong>Observed globally</strong><Link href="/threats">Open the observation</Link></li>
            <li><span>Organization relevance</span><strong>{threat ? matchLabel(threat.classification).label : "Unknown"}</strong>{threat ? <Link href={`/services/${lead?.service_id}?tab=technology`}>Open the technology evidence</Link> : <span>No match is stored.</span>}</li>
            <li><span>Business service</span><strong>{lead?.name ?? "Unknown"}</strong>{lead ? <Link href={`/services/${lead.service_id}?tab=situation`}>Open the service investigation</Link> : null}</li>
            <li><span>Candidate exposure</span><strong>{path ? path.evidence_state : "Unknown"}</strong>{path ? <Link href={`/services/${lead?.service_id}?tab=paths`}>Open the path</Link> : <span>No path is stored.</span>}</li>
            <li><span>Control readiness</span><strong>{journey?.controls?.[0]?.latest_evidence === "gap" ? "Configured, not observed" : journey?.controls?.[0]?.latest_evidence ?? "Unknown"}</strong>{lead ? <Link href={`/services/${lead.service_id}?tab=controls`}>Open the control</Link> : null}</li>
            <li><span>Required action</span><strong>{owner === "Unassigned" ? "Needs owner" : "Review required"}</strong><Link href={actionHref}>Open the action</Link></li>
          </ol>
        )}
      </section>
      <section aria-label="Material exploitation changes">
        <h2>Material exploitation changes</h2>
        {pending ? <p className="skeleton" aria-busy="true">Loading material exploitation changes.</p> : emerging.length > 0 ? (
          <ul>
            {emerging.slice(0, 3).map((item) => (
              <li key={item.cluster_id}>
                <strong>{item.cve || item.title}</strong>: {item.organization_relevance}. {item.required_action}.{" "}
                <Link href={`/threats/emerging/${item.cluster_id}`}>Open the cluster</Link>
              </li>
            ))}
          </ul>
        ) : (
          <p>No material exploitation change with organization technology relevance is stored. General news is excluded from the command center.</p>
        )}
      </section>
      <section aria-label="Readiness verification">
        <h2>Readiness verification</h2>
        {pending ? <p className="skeleton" aria-busy="true">Loading readiness recommendations.</p> : readiness && readiness.recommendations.length > 0 ? (
          <>
            <p>{readiness.services_needing_verification} services need verification. Manual approval is required. A recommendation is not a control failure.</p>
            <ul>
              {readiness.recommendations.slice(0, 3).map((item) => (
                <li key={item.id}>
                  <strong>{item.service}</strong>: {item.control}. Check: {item.check_title}. {item.approval_required ? "Approval required." : `State: ${item.state}.`} Owner: Unassigned.
                  {" "}
                  <Link href={item.service_node_id ? `/services/${item.service_node_id}?tab=controls` : "/services"}>Open the service</Link>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p>No verification recommendation is stored. Global observations alone do not create a customer control test.</p>
        )}
      </section>
      <section aria-label="Accountable actions">
        <h2>Accountable actions</h2>
        {pending || !actions ? (
          <p className="skeleton" aria-busy="true">Loading accountability summary.</p>
        ) : (
          <p>
            Unassigned {actions.unassigned}. Due soon {actions.due_soon}. Overdue {actions.overdue}. Awaiting evidence {actions.awaiting_evidence}. Ready for review {actions.ready_for_review}. Reopened {actions.reopened}.
            {" "}
            <Link href="/actions?status=awaiting_evidence">Open the action register</Link>.
            A closed action is not proof that related risk no longer exists. Deployment signatures are evidence-integrity metadata, not a security score.
          </p>
        )}
      </section>
      <section aria-label="Response coordination">
        <h2>Response coordination</h2>
        {pending || !responseSummary ? (
          <p className="skeleton" aria-busy="true">Loading response summary.</p>
        ) : (
          <p>
            Assessments active {responseSummary.assessments_active}. Exercises active {responseSummary.exercises_active}.
            Confirmed incidents {responseSummary.confirmed_incidents}. Decisions overdue {responseSummary.decisions_overdue}.
            Unfilled critical roles {responseSummary.unfilled_critical_roles}. {responseSummary.note}{" "}
            <Link href="/response">Open response workspaces</Link>.
          </p>
        )}
      </section>
        </div> : null}</>
      </details>
      <details id="attention" className="command-services" onToggle={(event) => setServicesOpen(event.currentTarget.open)}>
        <summary>{pending ? "Loading services" : `${reviewCount} services requiring attention`}</summary>
        {servicesOpen ? <section aria-label="Services requiring attention">
        <h2>Services requiring attention</h2>
        {pending ? <p className="skeleton" aria-busy="true">Loading the priority service.</p> : (
          <div className="outcome-row">
            {services.slice(0, 3).map((item) => (
              <article className="service-card" key={item.service_id}>
                <h3>{item.name}</h3>
                <p>{item.recommended_step.split(". ")[0].replace(/\.$/, "")}.</p>
                <p>{item.synthetic === false ? "Recorded" : "Synthetic"} · {item.live_count + item.reference_count} matches</p>
                <p>{item.control_gap || "Control evidence is on the service."}</p>
                <p>Owner: {item.service_id === lead?.service_id ? owner : "Unassigned"}</p>
                <p><Link className="btn" href={`/services/${item.service_id}?tab=situation`}>Open the service investigation</Link></p>
              </article>
            ))}
          </div>
        )}
      </section> : null}
      </details>
      {detailOpen ? <section className="known-grid" aria-label="Known versus uncertain">
        <h2>Known versus uncertain</h2>
        <div>
          <h3>Known</h3>
          <ul>
            <li>Global observations are stored separately from organization evidence.</li>
            <li>{lead ? `${lead.name} is a recorded service.` : "No service is stored."}</li>
            <li>{threat ? `Maturity: ${maturityStatement(threat.maturity)}` : "No technology match is stored."}</li>
          </ul>
        </div>
        <div>
          <h3>Needs validation</h3>
          <ul>
            <li>Owner: {pending ? "Loading control readiness" : owner}.</li>
            <li>{action || "No action is stored."}</li>
            <li>A country share is not organization exposure.</li>
          </ul>
        </div>
      </section> : null}
    </article>
  );
}
