"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";

import { api } from "@/lib/api";

type Detail = {
  title: string;
  summary: string;
  canonical_url: string | null;
  source_key: string;
  maturity: string;
  vendor: string;
  vendor_advisory_id: string;
  cves: string[];
  vendor_severity: string;
  cvss_score: number | null;
  cvss_version: string | null;
  kev_listed: boolean;
  epss_score: number | null;
  vex_status: string;
  exploitation_claim: string;
  geography: { role: string; country: string; note: string }[];
  products: { product: string; scheme: string; constraint: string; fixed: string; observed: string; comparison: string }[];
  synthetic_matches: { state: string; asset_key: string; services: { source_key?: string }[]; explanation: string; missing_facts: string[] }[];
  limitations: string[];
  priority_reason: string;
  enterprise_context: string;
};

export default function LandscapeDetailPage() {
  const params = useParams<{ id: string }>();
  const [item, setItem] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api<Detail>(`/api/v1/landscape/advisories/${params.id}`)
      .then(setItem)
      .catch(() => setError("This advisory is not available."));
  }, [params.id]);
  if (error) return <div className="stack"><p role="alert">{error}</p></div>;
  if (!item) return <div className="stack"><p>Loading advisory.</p></div>;
  return (
    <div className="stack">
      <p><Link href="/threats">Threats</Link></p>
      <h1>{item.title}</h1>
      <p>{item.summary}</p>
      <p>Source {item.source_key}, maturity {item.maturity}. Enterprise context: {item.enterprise_context}.</p>
      <p>Vendor advisory {item.vendor_advisory_id}. CVEs {item.cves.join(", ") || "none"}.</p>
      <p>Vendor severity {item.vendor_severity}. CVSS {item.cvss_score ?? "not supplied"} {item.cvss_version ?? ""}.</p>
      <p>KEV {item.kev_listed ? "listed" : "not listed"}. EPSS {item.epss_score ?? "not supplied"}. These are different facts.</p>
      <p>Product status {item.vex_status}. Exploitation claim {item.exploitation_claim}.</p>
      <p>{item.priority_reason}</p>
      {item.canonical_url ? <p><a href={item.canonical_url} rel="noreferrer">Authoritative source</a></p> : null}
      <h2>Products and versions</h2>
      <table>
        <thead>
          <tr>
            <th scope="col">Product</th>
            <th scope="col">Observed</th>
            <th scope="col">Constraint</th>
            <th scope="col">Fixed</th>
            <th scope="col">Comparison</th>
          </tr>
        </thead>
        <tbody>
          {item.products.map((product) => (
            <tr key={product.product}>
              <td>{product.product}</td>
              <td>{product.observed || "missing"}</td>
              <td>{product.constraint || "missing"}</td>
              <td>{product.fixed || "not supplied"}</td>
              <td>{product.comparison}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>Synthetic assets and services</h2>
      {item.synthetic_matches.length === 0 ? <p>No synthetic asset in this workspace matched these CVE identifiers.</p> : null}
      <ul>
        {item.synthetic_matches.map((match) => (
          <li key={match.asset_key}>
            {match.asset_key}: {match.state}. {match.explanation} Missing: {match.missing_facts.join(", ") || "none recorded"}.
          </li>
        ))}
      </ul>
      <h2>Geographic evidence</h2>
      <ul>
        {item.geography.map((geo) => (
          <li key={`${geo.role}-${geo.country}`}>{geo.country} as {geo.role}. {geo.note}</li>
        ))}
      </ul>
      <h2>Gaps</h2>
      <ul>{item.limitations.map((gap) => <li key={gap}>{gap}</li>)}</ul>
    </div>
  );
}
