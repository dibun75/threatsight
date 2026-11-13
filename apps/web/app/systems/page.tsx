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

type System = {
  id: string;
  name: string;
  display_name?: string;
  organisation?: string | null;
  technical_identifier?: string;
  record_origin?: string;
  origin_label?: string;
  labelled_synthetic?: boolean;
  supporting_inventory?: boolean;
  owner: string;
  environment: string;
  lifecycle: string;
  risk_classification: string | null;
};

export default function SystemsPage() {
  const [items, setItems] = useState<System[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<RecordScope>("showcase");

  async function load() {
    setItems(await api<System[]>(withScope("/api/v1/systems", scope)));
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [scope]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError(null);
    try {
      await api("/api/v1/systems", {
        method: "POST",
        body: JSON.stringify({
          name: form.get("name"),
          description: form.get("description") || null,
          owner: form.get("owner"),
          team: form.get("team") || null,
          environment: form.get("environment"),
          lifecycle: "draft",
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
        kicker="Inventory"
        title="AI systems"
        lede="AI systems registered for assurance. The labelled demo system is Nordic Retail’s Customer Support AI Assistant."
        actions={<ScopeToggle value={scope} onChange={setScope} />}
      />
      <form className="form" onSubmit={onSubmit}>
        <label>
          Name
          <input name="name" required maxLength={200} />
        </label>
        <label>
          Owner
          <input name="owner" required maxLength={200} />
        </label>
        <label>
          Team
          <input name="team" maxLength={200} />
        </label>
        <label>
          Environment
          <input name="environment" required maxLength={64} defaultValue="lab" />
        </label>
        <label>
          Description
          <textarea name="description" maxLength={20000} />
        </label>
        <button className="btn" type="submit">
          Register system
        </button>
      </form>
      <ErrorBanner message={error} />
      {!items ? (
        <LoadingState />
      ) : items.length === 0 ? (
        <EmptyState title="No systems yet" detail="Open Showcase and load the labelled demo, or register an AI system here." />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>System</th>
              <th>Origin</th>
              <th>Owner</th>
              <th>Environment</th>
              <th>Lifecycle</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <Link href={`/systems/${item.id}`}>{item.display_name || item.name}</Link>
                  {item.display_name && item.display_name !== item.name ? (
                    <div className="muted">Identifier {item.technical_identifier || item.name}</div>
                  ) : null}
                  {item.organisation ? <div className="muted">{item.organisation}</div> : null}
                  {item.supporting_inventory ? <div className="muted">Supporting labelled inventory</div> : null}
                </td>
                <td>
                  <StatusPill value={item.origin_label || item.record_origin || "USER / MANUAL"} />
                </td>
                <td>{item.owner}</td>
                <td>{item.environment}</td>
                <td>
                  <StatusPill value={item.lifecycle} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
