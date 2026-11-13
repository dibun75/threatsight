"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { PageHeader } from "@/components/PageHeader";
import { api } from "@/lib/api";

type Threat = { key: string; title: string; technique_count: number; mapped_techniques: number; evidence_state?: string };

export default function CatalogPage() {
  const [items, setItems] = useState<Threat[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<Threat[]>("/api/v1/threats").then(setItems).catch((err: Error) => setError(err.message));
  }, []);
  return (
    <div className="stack">
      <PageHeader kicker="Reference catalog" title="Technique catalog" lede="A curated, incomplete catalog. It is not the live advisory feed." />
      <ErrorBanner message={error} />
      {items.length === 0 ? <EmptyState title="No catalog rows" detail="The public demo does not load a new catalog." /> : (
        <div className="table-scroll" tabIndex={0} aria-label="Technique catalog. Scroll sideways inside this region if needed.">
          <table className="table">
            <thead><tr><th>Threat</th><th>Evidence</th><th>Techniques</th></tr></thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.key}><td><Link href={`/threats/${item.key}`}>{item.title}</Link></td><td>{item.evidence_state || "not assessed"}</td><td>{item.technique_count} listed, {item.mapped_techniques} mapped</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
