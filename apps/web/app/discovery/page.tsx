"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { ConfirmButton } from "@/components/ConfirmButton";
import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";

type Status = {
  adapter: string;
  demo_site_url: string;
  sources: number;
  assets: number;
  pending_signals: number;
  unrestricted_crawl: boolean;
  llm_may_authorize_fetch: boolean;
  legal_compliance_claim: boolean;
  synthetic_demo_labelled: boolean;
};

type Source = {
  id: string;
  url: string;
  title: string;
  owner: string;
  authorized: boolean;
  status: string;
  authorization_expires_at: string | null;
};

type Signal = {
  id: string;
  signal_kind: string;
  title: string;
  review_status: string;
  page_url: string;
};

export default function DiscoveryOverviewPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [sources, setSources] = useState<Source[]>([]);
  const [pending, setPending] = useState<Signal[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    const [st, src, signals] = await Promise.all([
      api<Status>("/api/v1/discovery/status"),
      api<Source[]>("/api/v1/discovery/sources"),
      api<Signal[]>("/api/v1/discovery/signals?review_status=pending"),
    ]);
    setStatus(st);
    setSources(src);
    setPending(signals);
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, []);

  async function bootstrap() {
    setError(null);
    setBusy(true);
    try {
      await api("/api/v1/discovery/demo/bootstrap", { method: "POST", body: "{}" });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bootstrap failed");
    } finally {
      setBusy(false);
    }
  }

  async function scan(sourceId: string) {
    setError(null);
    setBusy(true);
    try {
      await api(`/api/v1/discovery/sources/${sourceId}/scans`, {
        method: "POST",
        body: JSON.stringify({ confirm_execution: true }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="AI discovery"
        title="Authorized URL discovery"
        lede="Register the labelled synthetic demo site, fetch public pages within the allow-list, and review extracted AI-assurance signals. This is not a vulnerability scanner and does not crawl the public internet."
        actions={
          <ConfirmButton
            label="Register demo site"
            confirmLabel="Confirm register"
            disabled={busy}
            onConfirm={() => void bootstrap()}
          />
        }
      />
      <ErrorBanner message={error} />
      {status ? (
        <div className="metrics">
          <div className="metric">
            <b>{status.sources}</b>
            <span>Registered sources</span>
          </div>
          <div className="metric">
            <b>{status.assets}</b>
            <span>
              <Link href="/discovery/assets">Discovered assets</Link>
            </span>
          </div>
          <div className="metric">
            <b>{status.pending_signals}</b>
            <span>Pending review</span>
          </div>
          <div className="metric">
            <b>{String(status.unrestricted_crawl)}</b>
            <span>Unrestricted crawl</span>
          </div>
        </div>
      ) : (
        <LoadingState label="Loading discovery status…" />
      )}
      {status?.synthetic_demo_labelled ? (
        <p className="muted">
          Target is the synthetic Northwind Copilot site at <code>{status.demo_site_url}</code>. Adapter{" "}
          {status.adapter}. LLM fetch authority: {String(status.llm_may_authorize_fetch)}. Legal compliance claim:{" "}
          {String(status.legal_compliance_claim)}.
        </p>
      ) : null}
      <section>
        <h2>Sources</h2>
        {sources.length === 0 ? (
          <EmptyState
            title="No discovery sources"
            detail="Register the synthetic demo site. Arbitrary internet URLs are refused."
          />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Title</th>
                <th>URL</th>
                <th>Status</th>
                <th>Authorized</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sources.map((item) => (
                <tr key={item.id}>
                  <td>{item.title}</td>
                  <td>
                    <code>{item.url}</code>
                  </td>
                  <td>
                    <StatusPill value={item.status} />
                  </td>
                  <td>{item.authorized ? "yes" : "no"}</td>
                  <td>
                    <ConfirmButton
                      label="Scan"
                      confirmLabel="Confirm fetch"
                      disabled={busy}
                      onConfirm={() => void scan(item.id)}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section>
        <h2>Evidence candidates</h2>
        {pending.length === 0 ? (
          <EmptyState title="No pending signals" detail="Scan an authorized source, then review extracted statements." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Title</th>
                <th>Page</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {pending.map((item) => (
                <tr key={item.id}>
                  <td>{item.signal_kind}</td>
                  <td>{item.title}</td>
                  <td>
                    <code>{item.page_url}</code>
                  </td>
                  <td>
                    <StatusPill value={item.review_status} tone="review" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
