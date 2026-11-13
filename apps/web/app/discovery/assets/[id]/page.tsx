"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";

type Signal = {
  id: string;
  signal_kind: string;
  title: string;
  statement: string;
  quote: string;
  page_url: string;
  content_hash: string;
  review_status: string;
  evidence_id: string | null;
};

type Asset = {
  id: string;
  kind: string;
  title: string;
  url: string;
  summary: string | null;
  status: string;
  signals: Signal[];
};

type Control = { id: string; identifier: string; title: string };

export default function DiscoveryAssetDetailPage() {
  const params = useParams<{ id: string }>();
  const [asset, setAsset] = useState<Asset | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [mapControl, setMapControl] = useState<Record<string, string>>({});

  async function load() {
    const [detail, rows] = await Promise.all([
      api<Asset>(`/api/v1/discovery/assets/${params.id}`),
      api<Control[]>("/api/v1/controls"),
    ]);
    setAsset(detail);
    setControls(rows);
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [params.id]);

  async function review(signalId: string, decision: string) {
    setError(null);
    try {
      await api(`/api/v1/discovery/signals/${signalId}/review`, {
        method: "POST",
        body: JSON.stringify({ decision }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Review failed");
    }
  }

  async function mapToControl(signalId: string) {
    const controlId = mapControl[signalId];
    if (!controlId) {
      setError("Choose a control before mapping.");
      return;
    }
    setError(null);
    try {
      await api(`/api/v1/discovery/signals/${signalId}/map-control`, {
        method: "POST",
        body: JSON.stringify({ control_id: controlId }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Map failed");
    }
  }

  if (!asset) {
    return error ? <ErrorBanner message={error} /> : <LoadingState label="Loading asset…" />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="AI discovery"
        title={asset.title}
        lede={`${asset.kind} at ${asset.url}. Extracted statements are candidates until approved. Approval creates evidence with URL and content-hash provenance. It is not a legal compliance result.`}
        crumbs={[
          { href: "/discovery", label: "Discovery" },
          { href: "/discovery/assets", label: "Assets" },
          { label: asset.title },
        ]}
      />
      <ErrorBanner message={error} />
      <p className="muted">{asset.summary}</p>
      <p>
        Status <StatusPill value={asset.status} /> · <code>{asset.url}</code>
      </p>
      <section>
        <h2>Evidence candidates</h2>
        {asset.signals.length === 0 ? (
          <EmptyState title="No signals" detail="This page did not yield reviewable AI-assurance statements." />
        ) : (
          <div className="stack">
            {asset.signals.map((signal) => (
              <article key={signal.id} className="card">
                <p className="kicker">{signal.signal_kind}</p>
                <h3>{signal.title}</h3>
                <p>{signal.statement}</p>
                <blockquote>
                  <code>{signal.quote}</code>
                </blockquote>
                <p className="muted">
                  Hash <code>{signal.content_hash}</code> · <StatusPill value={signal.review_status} tone="review" />
                </p>
                {signal.review_status === "pending" ? (
                  <p className="confirm-pair">
                    <button className="btn" type="button" onClick={() => void review(signal.id, "approved")}>
                      Approve as evidence
                    </button>
                    <button className="btn secondary" type="button" onClick={() => void review(signal.id, "rejected")}>
                      Reject
                    </button>
                  </p>
                ) : null}
                {signal.review_status === "approved" && signal.evidence_id ? (
                  <p className="confirm-pair">
                    <label>
                      Map to control
                      <select
                        value={mapControl[signal.id] || ""}
                        onChange={(event) => setMapControl({ ...mapControl, [signal.id]: event.target.value })}
                      >
                        <option value="">Select…</option>
                        {controls.map((control) => (
                          <option key={control.id} value={control.id}>
                            {control.identifier} — {control.title}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button className="btn" type="button" onClick={() => void mapToControl(signal.id)}>
                      Map
                    </button>
                  </p>
                ) : null}
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
