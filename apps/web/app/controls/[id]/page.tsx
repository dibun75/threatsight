"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { useParams } from "next/navigation";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";
import { formatWhen } from "@/lib/time";
import { assuranceTone, findingStatusTone, freshnessTone, verdictTone } from "@/lib/status";

type Requirement = { id: string; title: string };
type Evidence = { id: string; title: string };
type Framework = { id: string; framework_key: string; reference_code: string; title: string };
type Assurance = {
  identifier: string;
  title: string;
  assurance_status: string;
  assurance_rationale: string | null;
  legal_compliance_claim: boolean;
  latest_technical_verdict: string | null;
  freshness: string | null;
  freshness_window_days: number | null;
  requirements: Requirement[];
  evidence: Evidence[];
  framework_mappings: Array<{ id: string; framework_key: string; reference_code: string; title: string }>;
  reviews: Array<{ id: string; reviewer: string; decision: string; comment: string | null }>;
};
type Run = {
  id: string;
  scenario_key: string;
  verdict: string;
  reason_code: string;
  finding_id: string | null;
  evidence_id: string | null;
  parent_run_id: string | null;
};
type Finding = { id: string; title: string; status: string; verdict: string; severity: string };
type Audit = { id: string; action: string; actor: string; at: string };

export default function ControlDetailPage() {
  const params = useParams<{ id: string }>();
  const [assurance, setAssurance] = useState<Assurance | null>(null);
  const [requirements, setRequirements] = useState<Requirement[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const [view, reqs, ev, refs, events, runRows, findingRows] = await Promise.all([
      api<Assurance>(`/api/v1/controls/${params.id}/assurance`),
      api<Requirement[]>("/api/v1/requirements"),
      api<Evidence[]>("/api/v1/evidence"),
      api<Framework[]>("/api/v1/framework-references"),
      api<Audit[]>(`/api/v1/audit?entity_type=control&entity_id=${params.id}`),
      api<Run[]>(`/api/v1/assurance/runs?control_id=${params.id}`),
      api<Finding[]>(`/api/v1/findings?control_id=${params.id}`),
    ]);
    setAssurance(view);
    setRequirements(reqs);
    setEvidence(ev);
    setFrameworks(refs);
    setAudit(events);
    setRuns(runRows);
    setFindings(findingRows);
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [params.id]);

  async function post(path: string, body: unknown) {
    setError(null);
    try {
      await api(path, { method: "POST", body: JSON.stringify(body) });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    }
  }

  async function onStatus(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError(null);
    try {
      await api(`/api/v1/controls/${params.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          assurance_status: form.get("assurance_status"),
          assurance_rationale: form.get("assurance_rationale") || null,
        }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed");
    }
  }

  if (!assurance) {
    return error ? <ErrorBanner message={error} /> : <LoadingState />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Control"
        title={`${assurance.identifier} · ${assurance.title}`}
        lede="Technical verdicts come from executed tests. Manual assurance status is a separate operator field. Legal compliance is never claimed."
        crumbs={[{ href: "/controls", label: "Controls" }, { label: assurance.identifier }]}
      />
      <p>
        Status: <StatusPill value={assurance.assurance_status} tone={assuranceTone(assurance.assurance_status)} />
        {assurance.latest_technical_verdict ? (
          <>
            {" "}
            · Latest verdict:{" "}
            <StatusPill value={assurance.latest_technical_verdict} tone={verdictTone(assurance.latest_technical_verdict)} />
          </>
        ) : null}{" "}
        {assurance.freshness ? (
          <>
            · Freshness: <StatusPill value={assurance.freshness} tone={freshnessTone(assurance.freshness)} />
            {assurance.freshness_window_days ? ` (${assurance.freshness_window_days}d)` : ""}{" "}
          </>
        ) : null}
        · legal claim {String(assurance.legal_compliance_claim)} · <Link href="/assurance">Run test</Link>
      </p>
      {assurance.assurance_rationale && <p className="lede">{assurance.assurance_rationale}</p>}
      <ErrorBanner message={error} />

      <section>
        <h2>Tests and retests</h2>
        {runs.length === 0 ? (
          <EmptyState title="No runs for this control" detail="Execute AUTH-01 or AUTH-02 from Tests." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Verdict</th>
                <th>Reason</th>
                <th>Links</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((item) => (
                <tr key={item.id}>
                  <td>
                    {item.scenario_key}
                    {item.parent_run_id ? " · retest" : ""}
                  </td>
                  <td>
                    <StatusPill value={item.verdict} tone={verdictTone(item.verdict)} />
                  </td>
                  <td>{item.reason_code}</td>
                  <td>
                    {item.finding_id ? <Link href={`/findings/${item.finding_id}`}>finding</Link> : null}
                    {item.evidence_id ? (
                      <>
                        {" "}
                        · <Link href={`/evidence/${item.evidence_id}`}>evidence</Link>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section>
        <h2>Findings</h2>
        {findings.length === 0 ? (
          <EmptyState title="No findings" detail="A FAIL with completed impact creates a finding." />
        ) : (
          <ul>
            {findings.map((item) => (
              <li key={item.id}>
                <Link href={`/findings/${item.id}`}>{item.title}</Link>{" "}
                <StatusPill value={item.verdict} tone={verdictTone(item.verdict)} />{" "}
                <StatusPill value={item.status} tone={findingStatusTone(item.status)} />
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>Map requirement</h2>
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            void post(`/api/v1/controls/${params.id}/requirements`, {
              requirement_id: form.get("requirement_id"),
              rationale: form.get("rationale") || null,
              provenance: "manual-ui",
            });
          }}
        >
          <label>
            Requirement
            <select name="requirement_id" required>
              {requirements.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.title}
                </option>
              ))}
            </select>
          </label>
          <label>
            Rationale
            <textarea name="rationale" maxLength={20000} />
          </label>
          <button className="btn" type="submit">
            Map
          </button>
        </form>
        <ul>
          {assurance.requirements.map((item) => (
            <li key={item.id}>
              <Link href={`/requirements/${item.id}`}>{item.title}</Link>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Attach evidence</h2>
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            void post(`/api/v1/controls/${params.id}/evidence/${form.get("evidence_id")}`, {});
          }}
        >
          <label>
            Evidence
            <select name="evidence_id" required>
              {evidence.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.title}
                </option>
              ))}
            </select>
          </label>
          <button className="btn" type="submit">
            Attach
          </button>
        </form>
        <ul>
          {assurance.evidence.map((item) => (
            <li key={item.id}>
              <Link href={`/evidence/${item.id}`}>{item.title}</Link>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Framework mapping</h2>
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            void post(`/api/v1/controls/${params.id}/framework-mappings`, {
              framework_reference_id: form.get("framework_reference_id"),
              note: "Informational mapping. Not a legal conclusion.",
            });
          }}
        >
          <label>
            Reference
            <select name="framework_reference_id" required>
              {frameworks.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.framework_key} {item.reference_code}
                </option>
              ))}
            </select>
          </label>
          <button className="btn" type="submit">
            Map informatively
          </button>
        </form>
        <ul>
          {assurance.framework_mappings.map((item) => (
            <li key={item.id}>
              {item.framework_key} {item.reference_code} — {item.title}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Manual assurance status</h2>
        <form className="form" onSubmit={onStatus}>
          <label>
            Status
            <select name="assurance_status" defaultValue={assurance.assurance_status}>
              <option value="VALIDATED">VALIDATED</option>
              <option value="PARTIALLY_VALIDATED">PARTIALLY_VALIDATED</option>
              <option value="GAP_DETECTED">GAP_DETECTED</option>
              <option value="EVIDENCE_REQUIRED">EVIDENCE_REQUIRED</option>
              <option value="HUMAN_REVIEW_REQUIRED">HUMAN_REVIEW_REQUIRED</option>
              <option value="NOT_APPLICABLE">NOT_APPLICABLE</option>
            </select>
          </label>
          <label>
            Rationale
            <textarea name="assurance_rationale" maxLength={20000} defaultValue={assurance.assurance_rationale ?? ""} />
          </label>
          <button className="btn" type="submit">
            Save status
          </button>
        </form>
      </section>

      <section>
        <h2>Review</h2>
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            void post("/api/v1/reviews", {
              entity_type: "control",
              entity_id: params.id,
              reviewer: form.get("reviewer"),
              decision: form.get("decision"),
              comment: form.get("comment") || null,
            });
          }}
        >
          <label>
            Reviewer
            <input name="reviewer" required defaultValue="operator" />
          </label>
          <label>
            Decision
            <select name="decision" defaultValue="approve">
              <option value="approve">approve</option>
              <option value="reject">reject</option>
              <option value="defer">defer</option>
              <option value="request_changes">request_changes</option>
            </select>
          </label>
          <label>
            Comment
            <textarea name="comment" />
          </label>
          <button className="btn" type="submit">
            Record review
          </button>
        </form>
        <ul>
          {assurance.reviews.map((item) => (
            <li key={item.id}>
              {item.reviewer}: {item.decision}
              {item.comment ? ` — ${item.comment}` : ""}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Audit</h2>
        <table className="table">
          <thead>
            <tr>
              <th>Action</th>
              <th>Actor</th>
              <th>When</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((item) => (
              <tr key={item.id}>
                <td>{item.action}</td>
                <td>{item.actor}</td>
                <td>{formatWhen(item.at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
