"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";

type ClusterDetail = {
  id: string;
  cve: string | null;
  title: string;
  exploitation_state: string;
  exploitation_explanation: string;
  headline?: string;
  what_changed: { type: string; reason: string; at: string; source: string }[];
  vendor_facts: { assertion_type: string; value: Record<string, unknown>; source_role: string }[];
  exploitation_observations: { assertion_type: string; value: Record<string, unknown> }[];
  exploitation_catalog?: { assertion_type: string; value: Record<string, unknown> }[];
  media_coverage: { title: string; canonical_url: string | null; published_at: string | null }[];
  government_status: { label: string; cisa_kev_listed: boolean; as_of?: string | null; note: string };
  probability_estimate: { label: string; epss_score: number | null; epss_date: string | null; note: string };
  organization_matches: {
    summary?: string;
    match_classification?: string;
    services?: { id: string; label: string; synthetic?: boolean }[];
    known_versus_unknown?: { known: string[]; unknown: string[] };
    recommended_verification?: { title: string; approval_required: boolean; note: string };
  };
  known_versus_unknown: { known: string[]; unknown: string[] } | unknown[];
  recommended_verification: { title: string; approval_required: boolean; note: string } | null;
  does_not_mean: string[];
  documents: { source_role: string; title: string; canonical_url: string | null; source_key: string }[];
  labels: Record<string, string>;
};

export default function EmergingClusterPage() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<ClusterDetail | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api<ClusterDetail>(`/api/v1/multisource/clusters/${params.id}`)
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, [params.id]);
  if (error) return <article className="stack"><p role="alert">{error}</p></article>;
  if (!data) return <p className="skeleton" aria-busy="true">Loading exploitation cluster.</p>;
  const kv = Array.isArray(data.known_versus_unknown)
    ? { known: [], unknown: [] }
    : (data.known_versus_unknown as { known: string[]; unknown: string[] }) || data.organization_matches?.known_versus_unknown || { known: [], unknown: [] };
  return (
    <article className="stack">
      <p className="kicker">Emerging exploitation</p>
      <h1>{data.title}</h1>
      <p>{data.headline || "Exploitation evidence incomplete"}.</p>
      <p>{data.cve}. Exploitation evidence state: {data.exploitation_state}. {data.exploitation_explanation}</p>
      <p>{data.does_not_mean.join(" ")}</p>

      <section>
        <h2>What changed</h2>
        {data.what_changed.length === 0 ? <p>No material change events are stored yet.</p> : (
          <ul>{data.what_changed.map((item) => <li key={`${item.at}-${item.type}`}>{item.at}: {item.reason} ({item.source})</li>)}</ul>
        )}
      </section>

      <section>
        <h2>Why it matters</h2>
        <p>{data.organization_matches?.summary || "No organization technology match is stored."}</p>
        <p>Match classification: {data.organization_matches?.match_classification || "unknown"}.</p>
      </section>

      <section>
        <h2>{data.labels?.vendor_advisory || "Siemens ProductCERT — Vendor advisory"}</h2>
        {data.vendor_facts.length === 0 ? <p>No vendor facts in this cluster.</p> : (
          <ul>
            {data.vendor_facts.map((item, index) => (
              <li key={index}>{item.assertion_type}: {JSON.stringify(item.value)}</li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>{data.labels?.researcher || "VulnCheck canary — Exploitation observed by researcher"}</h2>
        {data.exploitation_observations.length === 0 ? <p>No researcher exploitation observation is stored. Absence is not proof of no exploitation.</p> : (
          <ul>
            {data.exploitation_observations.map((item, index) => (
              <li key={index}>{item.assertion_type}: {JSON.stringify(item.value)}</li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>{data.labels?.catalog || "VulnCheck KEV — Exploitation catalog"}</h2>
        {(data.exploitation_catalog || []).length === 0 ? <p>No researcher exploitation catalog entry is stored.</p> : (
          <ul>
            {(data.exploitation_catalog || []).map((item, index) => (
              <li key={index}>{item.assertion_type}: {JSON.stringify(item.value)}</li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>{data.labels?.media || "The Hacker News — Media report"}</h2>
        {data.media_coverage.length === 0 ? <p>No media discovery metadata is stored.</p> : (
          <ul>
            {data.media_coverage.map((item) => (
              <li key={item.title}>{item.title}{item.canonical_url ? <> · <a href={item.canonical_url} rel="noopener noreferrer" target="_blank">Original source</a></> : null}</li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>{data.labels?.government || "CISA KEV"}</h2>
        <p>{data.government_status.cisa_kev_listed ? "Listed" : "Not listed"}{data.government_status.as_of ? ` as of ${data.government_status.as_of}` : ""}. {data.government_status.note}</p>
      </section>

      <section>
        <h2>{data.labels?.probability || "FIRST EPSS"}</h2>
        <p>{data.probability_estimate.epss_score == null ? "Value unavailable" : `Dated probability ${data.probability_estimate.epss_score}`}{data.probability_estimate.epss_date ? ` (${data.probability_estimate.epss_date})` : ""}. {data.probability_estimate.note}</p>
      </section>

      <section>
        <h2>Organization matches</h2>
        {(data.organization_matches?.services || []).map((service) => (
          <p key={service.id}>
            {service.label}{service.synthetic ? " (synthetic reference)" : ""}.{" "}
            <Link href={`/services/${service.id}`}>Open service</Link>
          </p>
        ))}
      </section>

      <section>
        <h2>Known versus unknown</h2>
        <p>Known: {(kv.known || []).join(" · ") || "None recorded."}</p>
        <p>Unknown: {(kv.unknown || []).join(" · ") || "None recorded."}</p>
      </section>

      <section>
        <h2>Recommended verification</h2>
        {data.recommended_verification || data.organization_matches?.recommended_verification ? (
          <p>
            {(data.recommended_verification || data.organization_matches?.recommended_verification)?.title}.{" "}
            {(data.recommended_verification || data.organization_matches?.recommended_verification)?.note}{" "}
            Approval required before any execution.
          </p>
        ) : (
          <p>No verification recommendation is stored.</p>
        )}
      </section>

      <section>
        <h2>Source timeline and provenance</h2>
        <ul>
          {data.documents.map((doc) => (
            <li key={`${doc.source_key}-${doc.title}`}>
              {doc.source_role}: {doc.title}
              {doc.canonical_url ? <> · <a href={doc.canonical_url} rel="noopener noreferrer" target="_blank">Canonical source</a></> : null}
            </li>
          ))}
        </ul>
      </section>

      <p><Link href="/threats?view=emerging">Back to Emerging exploitation</Link></p>
    </article>
  );
}
