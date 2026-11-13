"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";

type ResponseItem = {
  id: string;
  title: string;
  mode: string;
  lifecycle: string;
  declaration_state: string;
  affected_services: { key: string; name: string }[];
  response_lead: string | null;
  open_actions: number;
  next_review_at: string | null;
  synthetic_label: string | null;
  is_synthetic: boolean;
  is_incident: boolean;
};

export default function ResponseListPage() {
  const [items, setItems] = useState<ResponseItem[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    api<{ items: ResponseItem[] }>("/api/v1/response")
      .then((body) => setItems(body.items ?? []))
      .catch(() => setError("Response workspaces could not be loaded."));
  }, []);
  return (
    <article className="stack">
      <h1>Response</h1>
      <p>Coordinate assessments, exercises, and incident response. Activation is not an incident declaration.</p>
      {error ? <p role="alert">{error}</p> : null}
      <ul className="stack" aria-label="Response workspaces">
        {items.map((item) => (
          <li key={item.id}>
            <Link href={`/response/${item.id}`}>
              <strong>{item.title}</strong>
            </Link>
            {item.synthetic_label || item.mode === "exercise" ? (
              <p>
                <span className="badge">Synthetic exercise</span>
              </p>
            ) : null}
            <p>
              Mode: {item.mode} · Lifecycle: {item.lifecycle} · Declaration:{" "}
              {item.is_incident ? "confirmed_incident" : item.declaration_state}
              {item.mode === "exercise" && item.declaration_state !== "confirmed_incident"
                ? " (exercise — not an incident)"
                : ""}
            </p>
            <p>
              Services: {item.affected_services.map((s) => s.name).join(", ") || "None listed"} · Lead:{" "}
              {item.response_lead || "Unfilled"} · Open actions: {item.open_actions}
              {item.next_review_at ? ` · Next review: ${item.next_review_at}` : ""}
            </p>
          </li>
        ))}
        {!items.length && !error ? <li>No response workspaces yet.</li> : null}
      </ul>
    </article>
  );
}
