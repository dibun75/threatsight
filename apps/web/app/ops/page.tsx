"use client";

import { useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";

type Status = {
  milestone: string;
  env: string;
  database_ok: boolean;
  auth_mode: string;
  openapi_enabled: boolean;
  sandbox_default: boolean;
  kill_switch: boolean;
  assurance_adapter: string;
  discovery_adapter: string;
  checklist_pass: number;
  checklist_count: number;
  legal_compliance_claim: boolean;
};

type Checklist = { items: Array<{ id: string; title: string; ok: boolean; detail: string }> };
type Config = Record<string, unknown>;

export default function OpsPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [checklist, setChecklist] = useState<Checklist | null>(null);
  const [config, setConfig] = useState<Config | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api<Status>("/api/v1/ops/status"),
      api<Checklist>("/api/v1/ops/checklist"),
      api<Config>("/api/v1/ops/config"),
    ])
      .then(([nextStatus, nextChecklist, nextConfig]) => {
        setStatus(nextStatus);
        setChecklist(nextChecklist);
        setConfig(nextConfig);
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  if (!status) {
    return error ? <ErrorBanner message={error} /> : <LoadingState label="Loading operations…" />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Enterprise operations"
        title="Deployment status"
        lede="Runtime health, redacted configuration, and the deployment security checklist. Secrets are not displayed. This is not a legal compliance result."
      />
      <ErrorBanner message={error} />
      <div className="metrics">
        <div className="metric">
          <b>{status.milestone}</b>
          <span>Milestone · {status.env}</span>
        </div>
        <div className="metric">
          <b>{String(status.database_ok)}</b>
          <span>Database ready</span>
        </div>
        <div className="metric">
          <b>{status.auth_mode}</b>
          <span>Auth mode</span>
        </div>
        <div className="metric">
          <b>
            {status.checklist_pass}/{status.checklist_count}
          </b>
          <span>Checklist items passing</span>
        </div>
      </div>
      <p className="muted">
        OpenAPI {String(status.openapi_enabled)} · sandbox {String(status.sandbox_default)} · kill switch{" "}
        {String(status.kill_switch)} · adapters {status.assurance_adapter}/{status.discovery_adapter} · legal claim{" "}
        {String(status.legal_compliance_claim)}
      </p>
      <section>
        <h2>Security checklist</h2>
        {checklist?.items.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {checklist.items.map((item) => (
                <tr key={item.id}>
                  <td>{item.title}</td>
                  <td>
                    <StatusPill value={item.ok ? "pass" : "gap"} tone={item.ok ? "pass" : "gap"} />
                  </td>
                  <td className="muted">{item.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState title="No checklist" detail="Ops checklist is served by the API." />
        )}
      </section>
      <section>
        <h2>Redacted configuration</h2>
        {config ? (
          <table className="table">
            <thead>
              <tr>
                <th>Key</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(config).map(([key, value]) => (
                <tr key={key}>
                  <td>{key}</td>
                  <td className="muted">{String(value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </div>
  );
}
