"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { FormEvent, Suspense, useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { ScopeToggle } from "@/components/ScopeToggle";
import { api } from "@/lib/api";
import type { RecordScope } from "@/lib/scope";
import { withScope } from "@/lib/scope";
import { freshnessTone } from "@/lib/status";

type Evidence = {
  id: string;
  title: string;
  evidence_type: string;
  status: string;
  owner: string;
  integrity_hash: string | null;
  collected_at: string | null;
  freshness: string | null;
};

function EvidenceTable({ rows }: { rows: Evidence[] }) {
  if (rows.length === 0) {
    return <EmptyState title="No hashed envelopes yet" detail="Confirm AUTH-01 to capture a SHA-256 observation envelope." />;
  }
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Title</th>
          <th>Type</th>
          <th>Hash</th>
          <th>Freshness</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((item) => (
          <tr key={item.id}>
            <td>
              <Link href={`/evidence/${item.id}`}>{item.title}</Link>
            </td>
            <td>{item.evidence_type}</td>
            <td>{item.integrity_hash ? <code>{item.integrity_hash.slice(0, 12)}…</code> : "—"}</td>
            <td>
              {item.freshness ? <StatusPill value={item.freshness} tone={freshnessTone(item.freshness)} /> : "—"}
            </td>
            <td>
              <StatusPill value={item.status} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

type ManifestRow = {
  id: string;
  title: string;
  status: string;
  manifest_digest: string | null;
  closure_outcome: string | null;
  service_node_id: string | null;
};

function EvidenceSignatureStatus({ actionId }: { actionId: string }) {
  const [info, setInfo] = useState<{ label?: string; status?: string; state?: string; fingerprint?: string } | null>(null);
  useEffect(() => {
    api<{ label?: string; status?: string; state?: string; fingerprint?: string }>(`/api/v1/evidence/signing/actions/${actionId}/signature`)
      .then(setInfo)
      .catch(() => setInfo({ status: "unsigned", label: "Unsigned" }));
  }, [actionId]);
  if (!info) return <p>Checking deployment signature.</p>;
  return (
    <p>
      {info.label ?? (info.status === "unsigned" ? "Unsigned" : "Reference-signed evidence")}
      {info.state ? `. Verification ${info.state}` : ""}
      {info.fingerprint ? `. Key fingerprint ${info.fingerprint}` : ""}
      . Deployment signatures are not compliance proof.
    </p>
  );
}

function EvidencePage() {
  const search = useSearchParams();
  const service = search.get("service");
  const [items, setItems] = useState<Evidence[] | null>(null);
  const [manifests, setManifests] = useState<ManifestRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<RecordScope>("showcase");
  const [readOnly, setReadOnly] = useState(true);
  const [showNotes, setShowNotes] = useState(false);

  async function load() {
    const base = withScope("/api/v1/evidence", scope);
    const path = service ? `${base}${base.includes("?") ? "&" : "?"}service=${encodeURIComponent(service)}` : base;
    setItems(await api<Evidence[]>(path));
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [scope, service]);

  useEffect(() => {
    api<{ items: ManifestRow[] }>("/api/v1/readiness/actions")
      .then((body) => {
        const rows = (body.items ?? []).filter((row) => row.manifest_digest);
        setManifests(service ? rows.filter((row) => row.service_node_id === service) : rows);
      })
      .catch(() => setManifests([]));
  }, [service]);
  useEffect(() => {
    api<{ role: string }>("/api/v1/radar/workspace")
      .then((body) => setReadOnly(body.role === "viewer" || body.role === "auditor"))
      .catch(() => setReadOnly(true));
  }, []);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError(null);
    try {
      await api("/api/v1/evidence", {
        method: "POST",
        body: JSON.stringify({
          title: form.get("title"),
          description: form.get("description") || null,
          evidence_type: "manual",
          owner: form.get("owner"),
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
        kicker="Evidence explorer"
        title="Evidence"
        lede="An evidence envelope is a hashed record of what a test observed — the durable proof behind a verdict. Hashed test envelopes are listed first; manual notes stay collapsed below."
        actions={<ScopeToggle value={scope} onChange={setScope} />}
      />
      {service ? (
        <p>Filtered to this service. <Link href="/evidence">Clear filters</Link></p>
      ) : null}
      <section aria-label="Evidence manifest">
        <h2>Evidence manifest</h2>
        <p>
          Closure evidence manifests start as unsigned integrity digests. A later deployment signature proves only that this ThreatSight deployment signed the digest. It is not auditor approval, certification, or proof that a control works.
        </p>
        {manifests.length === 0 ? (
          <p>No closure evidence manifest is stored yet. Open a readiness action after authorized closure to generate an integrity digest.</p>
        ) : (
          manifests.map((row) => (
            <article className="service-card" key={row.id}>
              <h3>{row.title}</h3>
              <p>
                Status {row.status}. Closure outcome {row.closure_outcome ?? "not closed"}. Integrity digest {row.manifest_digest}.
              </p>
              <EvidenceSignatureStatus actionId={row.id} />
              <p>
                <Link href={`/actions?service=${row.service_node_id ?? ""}&status=${row.status}`}>Open filtered actions</Link>
              </p>
            </article>
          ))
        )}
      </section>
      {readOnly ? (
        <p>This demonstration is read-only. Existing evidence stays visible. A visitor cannot record new evidence.</p>
      ) : (
      <form className="form" onSubmit={onSubmit}>
        <label>
          Title
          <input name="title" required maxLength={200} />
        </label>
        <label>
          Owner
          <input name="owner" required maxLength={200} />
        </label>
        <label>
          Source reference
          <input name="source_reference" maxLength={500} />
        </label>
        <label>
          Description
          <textarea name="description" maxLength={20000} />
        </label>
        <button className="btn" type="submit">
          Record evidence
        </button>
      </form>
      )}
      <ErrorBanner message={error} />
      {!items ? (
        <LoadingState />
      ) : items.length === 0 ? (
        <EmptyState title={service ? "No linked evidence" : "No evidence yet"} detail={service ? "No linked evidence was found for this service." : "Load the labelled showcase or run CTRL-002 to produce a hashed envelope."} />
      ) : service ? (
        <EvidenceTable rows={items} />
      ) : (
        <>
          <EvidenceTable rows={items.filter((item) => item.integrity_hash || item.evidence_type === "test_artifact")} />
          {items.some((item) => !item.integrity_hash && item.evidence_type !== "test_artifact") ? (
            <details open={showNotes} onToggle={(event) => setShowNotes((event.target as HTMLDetailsElement).open)}>
              <summary>
                {items.filter((item) => !item.integrity_hash && item.evidence_type !== "test_artifact").length} manual
                notes and attestations
              </summary>
              <EvidenceTable
                rows={items.filter((item) => !item.integrity_hash && item.evidence_type !== "test_artifact")}
              />
            </details>
          ) : null}
        </>
      )}
    </div>
  );
}

export default function Page() {
  return <Suspense fallback={<p className="skeleton">Loading evidence.</p>}><EvidencePage /></Suspense>;
}
