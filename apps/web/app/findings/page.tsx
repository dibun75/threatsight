"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { FormEvent, Suspense, useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { ScopeToggle } from "@/components/ScopeToggle";
import { api } from "@/lib/api";
import type { RecordScope } from "@/lib/scope";
import { withScope } from "@/lib/scope";
import { findingStatusTone, severityTone, verdictTone } from "@/lib/status";

type Finding = {
  id: string;
  title: string;
  status: string;
  severity: string;
  verdict: string;
  summary: string;
  ai_system_name: string | null;
  ai_system_display_name?: string | null;
  control_identifier: string | null;
  control_id: string;
  evidence_id: string | null;
};

function ServiceContext() {
  const search = useSearchParams();
  const service = search.get("service");
  const match = search.get("match");
  const advisory = search.get("advisory");
  const recommendation = search.get("recommendation");
  const status = search.get("status");
  const [title, setTitle] = useState("");
  const [name, setName] = useState("");
  const [readiness, setReadiness] = useState<{ id: string; control: string; state: string; request_status: string | null; check_title: string }[]>([]);
  const [accountable, setAccountable] = useState<{ id: string; title: string; status: string; owner_subject: string | null; due_state: string | null; requirements_pending: number }[]>([]);
  useEffect(() => {
    if (service) {
      api<{ name: string; actions: { title: string }[] }>(`/api/v1/investigations/services/${service}`)
        .then((body) => {
          setName(body.name);
          setTitle(body.actions[0]?.title ?? "Validate the installed version and assign an owner.");
        })
        .catch(() => setName(""));
      api<{ recommendations: { id: string; service_node_id: string | null; control: string; state: string; request_status: string | null; check_title: string }[] }>("/api/v1/readiness/summary")
        .then((body) => {
          const rows = (body.recommendations ?? []).filter((row) => row.service_node_id === service);
          setReadiness(recommendation ? rows.filter((row) => row.id === recommendation) : rows);
        })
        .catch(() => setReadiness([]));
    }
    api<{ items: { id: string; title: string; status: string; owner_subject: string | null; due_state: string | null; requirements_pending: number; service_node_id: string | null }[] }>("/api/v1/readiness/actions")
      .then((body) => {
        let rows = body.items ?? [];
        if (service) rows = rows.filter((row) => row.service_node_id === service);
        if (status) rows = rows.filter((row) => row.status === status);
        setAccountable(rows);
      })
      .catch(() => setAccountable([]));
  }, [service, recommendation, status]);
  if (!service && !status) return null;
  const filters = [service ? "service" : "", match ? "match" : "", advisory ? "advisory" : "", recommendation ? "recommendation" : "", status ? "status" : ""].filter(Boolean).join(", ");
  return (
    <section className="decision-card" aria-label="Filtered action">
      <h2>{service ? "Filtered to this service" : "Filtered accountable actions"}</h2>
      {service ? <p>{name || "Loading the service context."}</p> : null}
      {service ? <p>{title || "Validate the installed version and assign an owner."}</p> : null}
      <p>Active filters: {filters}. Owner: Unassigned.</p>
      {readiness.length > 0 ? (
        <section aria-label="Verification approvals">
          <h3>Verification approvals</h3>
          {readiness.map((row) => (
            <p key={row.id}>
              Recommendation {row.state}. Check {row.check_title}. Control {row.control}. Execution {row.request_status ?? "not started"}.
              A verification approval is separate from an assurance finding.
            </p>
          ))}
        </section>
      ) : null}
      {accountable.length > 0 ? (
        <section aria-label="Accountable readiness actions">
          <h3>Accountable readiness actions</h3>
          {accountable.map((row) => (
            <p key={row.id}>
              {row.title}. Status {row.status}. Owner {row.owner_subject ?? "Unassigned"}. Due {row.due_state ?? "not set"}. Pending requirements {row.requirements_pending}.
              Synthetic reference. A closed action is not proof that related risk no longer exists.
            </p>
          ))}
        </section>
      ) : null}
      <p>
        {match ? <Link href={`/exposure/matches/${match}`}>Open the match</Link> : null}
        {advisory ? <> · <Link href={`/threats/advisories/${advisory}`}>Open the advisory</Link></> : null}
        {" · "}
        <Link href="/actions">Clear filters</Link>
      </p>
    </section>
  );
}

function FindingsList({ items, error }: { items: Finding[] | null; error: string | null }) {
  const service = useSearchParams().get("service");
  if (service) return <p>Assurance findings outside this service stay hidden while the service filter is active.</p>;
  return (
    <>
      <ErrorBanner message={error} />
      {!items ? (
        <LoadingState />
      ) : items.length === 0 ? (
        <EmptyState title="No findings" detail="Open Showcase, confirm AUTH-01 on the synthetic agent, then return here." />
      ) : (
        <table className="table">
          <caption>Assurance findings. These are not the service decision.</caption>
          <thead>
            <tr>
              <th>Title</th>
              <th>System / control</th>
              <th>Severity</th>
              <th>Verdict</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <Link href={`/findings/${item.id}`}>{item.title}</Link>
                </td>
                <td>
                  {item.ai_system_display_name || item.ai_system_name || "—"} ·{" "}
                  <Link href={`/controls/${item.control_id}`}>{item.control_identifier || "control"}</Link>
                </td>
                <td>
                  <StatusPill value={item.severity} tone={severityTone(item.severity)} />
                </td>
                <td>
                  <StatusPill value={item.verdict} tone={verdictTone(item.verdict)} />
                </td>
                <td>
                  <StatusPill value={item.status} tone={findingStatusTone(item.status)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

export default function FindingsPage() {
  const pathname = usePathname();
  const actions = pathname === "/actions" || pathname.startsWith("/actions/");
  const [items, setItems] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [scope, setScope] = useState<RecordScope>("showcase");

  async function load(nextStatus = status, nextSeverity = severity) {
    const params = new URLSearchParams();
    if (nextStatus) {
      params.set("status", nextStatus);
    }
    if (nextSeverity) {
      params.set("severity", nextSeverity);
    }
    const suffix = params.toString() ? `?${params}` : "";
    setItems(await api<Finding[]>(withScope(`/api/v1/findings${suffix}`, scope)));
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [scope]);

  async function onFilter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    try {
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Filter failed");
    }
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Assurance"
        title={actions ? "Actions" : "Findings"}
        lede="A finding is an open gap: a failed test with recorded impact. Open one to see what happened, the hashed evidence, any fix applied, and the re-test that closes it."
        actions={<ScopeToggle value={scope} onChange={setScope} />}
      />
      <form className="toolbar" onSubmit={onFilter}>
        <label>
          Status
          <select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">any</option>
            <option value="open">open</option>
            <option value="remediated">remediated</option>
            <option value="resolved">resolved</option>
          </select>
        </label>
        <label>
          Severity
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">any</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
        </label>
        <button className="btn" type="submit">
          Apply
        </button>
      </form>
      {actions ? <Suspense fallback={<p className="skeleton">Loading the service context.</p>}><ServiceContext /></Suspense> : null}
      <Suspense fallback={<p className="skeleton">Loading the action register.</p>}>
        <FindingsList items={items} error={error} />
      </Suspense>
    </div>
  );
}
