"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { ScopeToggle } from "@/components/ScopeToggle";
import { api } from "@/lib/api";
import type { RecordScope } from "@/lib/scope";
import { withScope } from "@/lib/scope";

type Requirement = {
  id: string;
  title: string;
  status: string;
  source_type: string;
  version: number;
};

export default function RequirementsPage() {
  const [items, setItems] = useState<Requirement[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<RecordScope>("showcase");

  async function load() {
    setItems(await api<Requirement[]>(withScope("/api/v1/requirements", scope)));
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [scope]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError(null);
    try {
      await api("/api/v1/requirements", {
        method: "POST",
        body: JSON.stringify({
          title: form.get("title"),
          statement: form.get("statement"),
          source_type: form.get("source_type"),
          source_reference: form.get("source_reference") || null,
        }),
      });
      event.currentTarget.reset();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create failed");
    }
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Governance"
        title="Requirements"
        lede="Candidate obligations until a human review records a decision. Approved document candidates appear here as records, not legal conclusions."
        actions={<ScopeToggle value={scope} onChange={setScope} />}
      />
      <form className="form" onSubmit={onSubmit}>
        <label>
          Title
          <input name="title" required maxLength={200} />
        </label>
        <label>
          Statement
          <textarea name="statement" required maxLength={20000} />
        </label>
        <label>
          Source type
          <select name="source_type" defaultValue="manual">
            <option value="manual">manual</option>
            <option value="policy">policy</option>
            <option value="regulation">regulation</option>
            <option value="standard">standard</option>
            <option value="contract">contract</option>
          </select>
        </label>
        <label>
          Source reference
          <input name="source_reference" maxLength={500} />
        </label>
        <button className="btn" type="submit">
          Create requirement
        </button>
      </form>
      <ErrorBanner message={error} />
      {!items ? (
        <LoadingState />
      ) : items.length === 0 ? (
        <EmptyState title="No requirements" detail="Open Showcase to load the labelled CTRL-002 requirement, or create one here." />
      ) : (
      <table className="table">
        <thead>
          <tr>
            <th>Title</th>
            <th>Source</th>
            <th>Status</th>
            <th>Version</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>
                <Link href={`/requirements/${item.id}`}>{item.title}</Link>
              </td>
              <td>{item.source_type}</td>
              <td>
                <StatusPill value={item.status} />
              </td>
              <td>{item.version}</td>
            </tr>
          ))}
        </tbody>
      </table>
      )}
    </div>
  );
}
