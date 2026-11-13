"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";

type PathItem = { state: string; freshness: string; evidence_modes: string[]; explanation: string };
type Decision = {
  service_id: string;
  name: string;
  paths: PathItem[];
  path_count: number;
  control_gap: string;
  recommended_step: string;
};

export default function PathsPage() {
  const [items, setItems] = useState<Decision[]>([]);
  const [serviceId, setServiceId] = useState("all");
  const [staleOnly, setStaleOnly] = useState(false);
  useEffect(() => {
    api<{ services: Decision[] }>("/api/v1/decisions/services").then((body) => setItems(body.services)).catch(() => setItems([]));
  }, []);
  const shown = items.filter((item) => serviceId === "all" || item.service_id === serviceId);
  return (
    <article className="stack">
      <h1>Candidate paths</h1>
      <p>A path is listed under a service only when a stored node key equals that service or one of its members. A candidate path is not an actual attack.</p>
      <label className="form">Service
        <select value={serviceId} onChange={(event) => setServiceId(event.target.value)}>
          <option value="all">All services</option>
          {items.map((item) => <option key={item.service_id} value={item.service_id}>{item.name}</option>)}
        </select>
      </label>
      <button className="btn secondary" type="button" aria-pressed={staleOnly} onClick={() => setStaleOnly((value) => !value)}>Stale only</button>
      {shown.map((item) => (
        <section key={item.service_id}>
          <h2>{item.name}</h2>
          <p>{item.path_count} candidate result{item.path_count === 1 ? "" : "s"}. {item.control_gap}</p>
          {item.paths.filter((path) => !staleOnly || path.freshness === "stale").map((path) => (
            <p key={path.explanation}>{path.evidence_modes.join(", ") || "unclassified"} · {path.state} · {path.freshness}. {path.explanation}</p>
          ))}
          <p>Recommended next step: {item.recommended_step}</p>
          <p><Link href={`/services/${item.service_id}`}>Open the service</Link></p>
        </section>
      ))}
      <div className="table-scroll" tabIndex={0} aria-label="Path legend.">
        <table>
          <caption>Relationship legend</caption>
          <thead><tr><th scope="col">Mark</th><th scope="col">Meaning</th></tr></thead>
          <tbody>
            <tr><th scope="row">Solid</th><td>Observed relationship</td></tr>
            <tr><th scope="row">Dashed</th><td>Configured relationship</td></tr>
            <tr><th scope="row">Dotted</th><td>Inferred relationship</td></tr>
            <tr><th scope="row">Double border</th><td>Unknown or unsupported join</td></tr>
          </tbody>
        </table>
      </div>
    </article>
  );
}
