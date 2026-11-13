"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { ScopeToggle } from "@/components/ScopeToggle";
import { upload, api } from "@/lib/api";
import type { RecordScope } from "@/lib/scope";
import { withScope } from "@/lib/scope";

type DocumentRow = {
  id: string;
  title: string;
  status: string;
  current_version: number;
  latest_hash: string | null;
  latest_media_kind: string | null;
  candidate_count: number;
};

export default function DocumentsPage() {
  const [items, setItems] = useState<DocumentRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [scope, setScope] = useState<RecordScope>("showcase");

  async function load() {
    setItems(await api<DocumentRow[]>(withScope("/api/v1/documents", scope)));
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [scope]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const file = data.get("file");
    if (!(file instanceof File) || file.size === 0) {
      setError("Choose a PDF, DOCX, Markdown, or text file.");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const title = String(data.get("title") || "").trim();
      await upload("/api/v1/documents", file, title ? { title } : undefined);
      form.reset();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Document intelligence"
        title="Documents"
        lede="Upload policy or regulatory material. Extraction produces candidates with source provenance. Nothing becomes an authoritative requirement until a human approves it. Showcase view has no labelled documents."
        actions={<ScopeToggle value={scope} onChange={setScope} />}
      />
      <form className="form" onSubmit={onSubmit}>
        <label>
          Title
          <input name="title" maxLength={200} placeholder="Optional" />
        </label>
        <label>
          File
          <input name="file" type="file" accept=".pdf,.docx,.txt,.md,text/plain,text/markdown,application/pdf" required />
        </label>
        <button className="btn" type="submit" disabled={busy}>
          {busy ? "Processing…" : "Upload and extract"}
        </button>
      </form>
      <ErrorBanner message={error} />
      {!items ? (
        <LoadingState />
      ) : items.length === 0 ? (
        <EmptyState title="No documents" detail="Upload a PDF, DOCX, Markdown, or text file. Extraction stays a candidate until human approval." />
      ) : (
      <table className="table">
        <thead>
          <tr>
            <th>Title</th>
            <th>Status</th>
            <th>Version</th>
            <th>Kind</th>
            <th>Candidates</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>
                <Link href={`/documents/${item.id}`}>{item.title}</Link>
              </td>
              <td>
                <StatusPill value={item.status} />
              </td>
              <td>{item.current_version}</td>
              <td>{item.latest_media_kind || "—"}</td>
              <td>{item.candidate_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
      )}
    </div>
  );
}
