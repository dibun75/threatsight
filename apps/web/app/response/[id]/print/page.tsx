"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";

type Detail = {
  title: string;
  mode: string;
  lifecycle: string;
  declaration_state: string;
  known_facts: string;
  uncertain_facts: string;
  reason: string;
  synthetic_label: string | null;
  is_synthetic: boolean;
  services: { service_name: string }[];
  actions: { title: string; status: string; owner: string | null }[];
  decisions: { decision: string; rationale: string }[];
  response_lead: string | null;
};

export default function ResponsePrintPage() {
  const params = useParams<{ id: string }>();
  const [detail, setDetail] = useState<Detail | null>(null);
  useEffect(() => {
    if (!params?.id) return;
    api<Detail>(`/api/v1/response/${params.id}`).then(setDetail).catch(() => setDetail(null));
  }, [params?.id]);
  if (!detail) {
    return <p>Loading printable situation report…</p>;
  }
  const exercise = detail.is_synthetic || detail.mode === "exercise";
  return (
    <article className="stack printable-sitrep">
      <h1>Situation report — {detail.title}</h1>
      {exercise ? <p>Synthetic exercise</p> : null}
      <ol>
        <li>
          <strong>Current status:</strong> {detail.lifecycle} / {detail.mode}
        </li>
        <li>
          <strong>Declaration state:</strong> {detail.declaration_state}
          {exercise ? " (exercise — not an incident)" : ""}
        </li>
        <li>
          <strong>What changed:</strong> {detail.reason}
        </li>
        <li>
          <strong>Business services involved:</strong> {detail.services.map((s) => s.service_name).join(", ") || "None"}
        </li>
        <li>
          <strong>Known facts:</strong> {detail.known_facts}
        </li>
        <li>
          <strong>Uncertain/conflicting facts:</strong> {detail.uncertain_facts}
        </li>
        <li>
          <strong>Actions and owners:</strong>{" "}
          {detail.actions.map((a) => `${a.title} (${a.status}${a.owner ? `, ${a.owner}` : ""})`).join("; ") || "None"}
        </li>
        <li>
          <strong>Decisions required / recorded:</strong>{" "}
          {detail.decisions.map((d) => d.decision).join("; ") || "None"}
        </li>
        <li>
          <strong>Evidence freshness:</strong> See pinned evidence on the response workspace.
        </li>
        <li>
          <strong>External communication state:</strong> Draft — not sent
        </li>
        <li>
          <strong>Regulatory assessment state:</strong> not_determined unless liaison confirmed
        </li>
        <li>
          <strong>Lead / next review:</strong> {detail.response_lead || "Unfilled"}
        </li>
      </ol>
      <p>Not legal advice. Signature on a response snapshot proves integrity only.</p>
    </article>
  );
}
