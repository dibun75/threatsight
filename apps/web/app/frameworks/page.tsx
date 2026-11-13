"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { ConfirmButton } from "@/components/ConfirmButton";
import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";
import { ASSURANCE_STATUSES, assuranceTone } from "@/lib/status";

type Framework = {
  key: string;
  title: string;
  locator: string;
  item_count: number;
  mapped_items: number;
  by_coverage_status: Record<string, number>;
  catalog_complete: boolean;
  legal_compliance_claim: boolean;
};

export default function FrameworksPage() {
  const [items, setItems] = useState<Framework[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setItems(await api<Framework[]>("/api/v1/frameworks"));
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, []);

  async function bootstrap() {
    setError(null);
    setBusy(true);
    try {
      await api("/api/v1/frameworks/demo/bootstrap", { method: "POST", body: "{}" });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bootstrap failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Framework assurance"
        title="Informational framework mappings"
        lede="Curated, incomplete pointers into public frameworks. Coverage is derived from mapped control assurance statuses. This is not a legal compliance result."
        actions={
          <ConfirmButton
            label="Load catalog"
            confirmLabel="Confirm catalog load"
            disabled={busy}
            onConfirm={() => void bootstrap()}
          />
        }
      />
      <ErrorBanner message={error} />
      {items.length === 0 ? (
        <EmptyState title="No catalog yet" detail="Load the curated M6 catalog. It is informational and incomplete." />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Framework</th>
              <th>Items</th>
              <th>Mapped</th>
              <th>Gap</th>
              <th>Validated</th>
              <th>Complete</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.key}>
                <td>
                  <Link href={`/frameworks/${item.key}`}>{item.title}</Link>
                  <div className="muted">{item.key}</div>
                </td>
                <td>{item.item_count}</td>
                <td>{item.mapped_items}</td>
                <td>
                  <StatusPill
                    value={String(item.by_coverage_status.GAP_DETECTED || 0)}
                    tone={item.by_coverage_status.GAP_DETECTED ? "gap" : "neutral"}
                  />
                </td>
                <td>
                  <StatusPill
                    value={String(item.by_coverage_status.VALIDATED || 0)}
                    tone={assuranceTone("VALIDATED")}
                  />
                </td>
                <td>{String(item.catalog_complete)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="muted">
        Status vocabulary: {ASSURANCE_STATUSES.join(", ")}. Legal compliance claim is always false.
      </p>
    </div>
  );
}
