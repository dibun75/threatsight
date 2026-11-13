"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";

type Decision = {
  service_id: string;
  name: string;
  state: string;
  explanation: string;
  live_count: number;
  reference_count: number;
  path_count: number;
  control_count: number;
  synthetic: boolean;
};

const STATE_LABEL: Record<string, string> = {
  action_required: "Action required",
  investigation_required: "Investigation required",
  evidence_stale: "Evidence stale",
  verified_current: "Verified for the recorded scope",
  no_current_relevant_match: "No current relevant match",
  insufficient_data: "Insufficient data",
};

export default function ServicesPage() {
  const [items, setItems] = useState<Decision[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    api<{ services: Decision[] }>("/api/v1/decisions/services")
      .then((body) => setItems(body.services))
      .catch(() => setError("Services could not be loaded."));
  }, []);
  return (
    <article className="stack">
      <h1>Services</h1>
      <p>Services that need a decision. There is no combined score.</p>
      {error ? <p role="alert">{error}</p> : null}
      <div className="outcome-row">
        {items.map((item) => (
          <article className="service-card" key={item.service_id}>
            <p>{item.synthetic ? "Synthetic" : "Recorded"} · {STATE_LABEL[item.state] || item.state}</p>
            <h2>{item.name}</h2>
            <p title={item.explanation}>{item.explanation.split(". ")[0].replace(/\.$/, "")}.</p>
            <p>{item.live_count} live · {item.reference_count} reference · {item.path_count} paths · {item.control_count} controls</p>
            <p>Owner: Unassigned</p>
            <p><Link href={`/services/${item.service_id}?tab=situation`}>Open</Link></p>
          </article>
        ))}
      </div>
    </article>
  );
}
