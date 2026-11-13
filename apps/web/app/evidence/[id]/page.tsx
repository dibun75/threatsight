"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";
import { findingStatusTone, freshnessTone, verdictTone } from "@/lib/status";
import { formatWhen } from "@/lib/time";

type Evidence = {
  id: string;
  title: string;
  description: string | null;
  evidence_type: string;
  source_reference: string | null;
  provenance: string | null;
  owner: string;
  status: string;
  control_ids: string[];
  ai_system_ids: string[];
  control_labels?: string[];
  system_labels?: string[];
  integrity_hash: string | null;
  envelope: Record<string, unknown> | null;
  collected_at: string | null;
  created_at: string;
  updated_at: string;
  freshness: string | null;
  freshness_window_days: number | null;
};

type Finding = {
  id: string;
  title: string;
  status: string;
  verdict: string;
};

export default function EvidenceDetailPage() {
  const params = useParams<{ id: string }>();
  const [item, setItem] = useState<Evidence | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api<Evidence>(`/api/v1/evidence/${params.id}`),
      api<Finding[]>(`/api/v1/findings?evidence_id=${params.id}`),
    ])
      .then(([evidence, linked]) => {
        setItem(evidence);
        setFindings(linked);
      })
      .catch((err: Error) => setError(err.message));
  }, [params.id]);

  if (!item) {
    return error ? <ErrorBanner message={error} /> : <LoadingState />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Evidence"
        title={item.title}
        lede={item.description || "No description."}
        crumbs={[{ href: "/evidence", label: "Evidence" }, { label: item.title }]}
      />
      <ul>
        <li>Type: {item.evidence_type}</li>
        <li>Owner: {item.owner}</li>
        <li>
          Status: <StatusPill value={item.status} />
        </li>
        <li>Source: {item.source_reference || "—"}</li>
        <li>Provenance: {item.provenance || "—"}</li>
        <li>Collected: {formatWhen(item.collected_at || item.created_at)}</li>
        {item.freshness ? (
          <li>
            Freshness: <StatusPill value={item.freshness} tone={freshnessTone(item.freshness)} />
            {item.freshness_window_days ? ` · ${item.freshness_window_days}-day window` : ""}
          </li>
        ) : null}
        {item.integrity_hash ? (
          <li>
            SHA-256: <code>{item.integrity_hash}</code>
          </li>
        ) : null}
      </ul>
      <ErrorBanner message={error} />
      <section>
        <h2>Linked controls and systems</h2>
        {item.control_ids.length === 0 && item.ai_system_ids.length === 0 ? (
          <EmptyState title="No links" detail="Attach this record to a control from the control page." />
        ) : (
          <ul>
            {item.control_ids.map((id, index) => (
              <li key={id}>
                Control: <Link href={`/controls/${id}`}>{item.control_labels?.[index] || "CTRL-002"}</Link>
              </li>
            ))}
            {item.ai_system_ids.map((id, index) => (
              <li key={id}>
                System: <Link href={`/systems/${id}`}>{item.system_labels?.[index] || "Customer Support AI Assistant"}</Link>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h2>Linked findings</h2>
        {findings.length === 0 ? (
          <p className="muted">No finding references this envelope.</p>
        ) : (
          <ul>
            {findings.map((finding) => (
              <li key={finding.id}>
                <Link href={`/findings/${finding.id}`}>{finding.title}</Link>{" "}
                <StatusPill value={finding.verdict} tone={verdictTone(finding.verdict)} />{" "}
                <StatusPill value={finding.status} tone={findingStatusTone(finding.status)} />
              </li>
            ))}
          </ul>
        )}
      </section>
      {item.envelope ? (
        <section className="card">
          <h2>Envelope</h2>
          <pre>{JSON.stringify(item.envelope, null, 2)}</pre>
        </section>
      ) : null}
    </div>
  );
}
