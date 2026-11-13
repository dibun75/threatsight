"use client";

import { FormEvent, useEffect, useState } from "react";
import { useParams } from "next/navigation";

import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";

type Requirement = {
  id: string;
  title: string;
  statement: string;
  source_type: string;
  source_reference: string | null;
  status: string;
  version: number;
};

export default function RequirementDetailPage() {
  const params = useParams<{ id: string }>();
  const [item, setItem] = useState<Requirement | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setItem(await api<Requirement>(`/api/v1/requirements/${params.id}`));
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [params.id]);

  async function onReview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError(null);
    try {
      await api("/api/v1/reviews", {
        method: "POST",
        body: JSON.stringify({
          entity_type: "requirement",
          entity_id: params.id,
          reviewer: form.get("reviewer"),
          decision: form.get("decision"),
          comment: form.get("comment") || null,
        }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Review failed");
    }
  }

  if (error && !item) {
    return <ErrorBanner message={error} />;
  }
  if (!item) {
    return <LoadingState />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Governance"
        title={item.title}
        lede={item.statement}
        crumbs={[{ href: "/requirements", label: "Requirements" }, { label: item.title }]}
      />
      <ErrorBanner message={error} />
      <ul>
        <li>Source: {item.source_type}</li>
        <li>Reference: {item.source_reference || "—"}</li>
        <li>
          Status: <StatusPill value={item.status} />
        </li>
        <li>Version: {item.version}</li>
      </ul>
      <h2>Human review</h2>
      <form className="form" onSubmit={onReview}>
        <label>
          Reviewer
          <input name="reviewer" required maxLength={200} defaultValue="operator" />
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
          <textarea name="comment" maxLength={20000} />
        </label>
        <button className="btn" type="submit">
          Record review
        </button>
      </form>
    </div>
  );
}
