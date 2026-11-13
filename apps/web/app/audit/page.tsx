"use client";

import { useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { api } from "@/lib/api";
import { formatWhen } from "@/lib/time";

type Event = {
  id: string;
  at: string;
  actor: string;
  action: string;
  entity_type: string;
  entity_id: string;
};

export default function AuditPage() {
  const [items, setItems] = useState<Event[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Event[]>("/api/v1/audit?order=desc&limit=100")
      .then(setItems)
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <div className="stack">
      <PageHeader
        kicker="Enterprise operations"
        title="Audit log"
        lede="Append-only mutations. Newest first. Export the same stream from Exports. This is attribution, not a legal conclusion."
      />
      <ErrorBanner message={error} />
      {!items ? (
        <LoadingState />
      ) : items.length === 0 ? (
        <EmptyState title="No audit events yet" detail="Mutating API calls write an audit row." />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>When</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Entity</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td className="muted">{formatWhen(item.at)}</td>
                <td>{item.actor}</td>
                <td>{item.action}</td>
                <td>
                  {item.entity_type}
                  <div className="muted">{item.entity_id}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
