"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";

type Asset = {
  id: string;
  kind: string;
  title: string;
  url: string;
  status: string;
  pending_signals: number;
};

export default function DiscoveryAssetsPage() {
  const [items, setItems] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Asset[]>("/api/v1/discovery/assets")
      .then(setItems)
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <div className="stack">
      <PageHeader
        kicker="AI discovery"
        title="Discovered assets"
        lede="Public pages identified from an authorized, allow-listed fetch. Signals remain candidates until a human approves them."
        crumbs={[
          { href: "/discovery", label: "Discovery" },
          { label: "Assets" },
        ]}
      />
      <ErrorBanner message={error} />
      {items.length === 0 ? (
        <EmptyState title="No assets" detail="Register and scan the synthetic demo site from Discovery." />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Title</th>
              <th>Kind</th>
              <th>URL</th>
              <th>Pending</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <Link href={`/discovery/assets/${item.id}`}>{item.title}</Link>
                </td>
                <td>{item.kind}</td>
                <td>
                  <code>{item.url}</code>
                </td>
                <td>{item.pending_signals}</td>
                <td>
                  <StatusPill value={item.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
