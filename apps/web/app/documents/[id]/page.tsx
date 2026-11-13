"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { useParams } from "next/navigation";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api, upload } from "@/lib/api";
import { formatWhen } from "@/lib/time";

type Version = {
  id: string;
  version_number: number;
  original_filename: string;
  media_kind: string;
  content_hash: string;
  page_count: number | null;
  extraction_status: string;
  extraction_provider: string | null;
  extraction_model: string | null;
  extracted_at: string | null;
  extraction_warnings: string[];
};

type Candidate = {
  id: string;
  version_number: number;
  candidate_type: string;
  review_status: string;
  title: string;
  statement: string;
  confidence: number;
  authoritative_requirement_id: string | null;
  authoritative_control_id: string | null;
  provenance: {
    content_hash: string;
    page: number | null;
    section: string | null;
    quote: string;
    extracted_at: string;
    extraction_method: string;
    extraction_model: string;
  };
};

type Control = { id: string; identifier: string; title: string };

type Audit = { id: string; action: string; actor: string; at: string; payload: Record<string, unknown> };

type DocumentDetail = {
  id: string;
  title: string;
  status: string;
  current_version: number;
  failure_reason: string | null;
  versions: Version[];
  candidates: Candidate[];
};

export default function DocumentDetailPage() {
  const params = useParams<{ id: string }>();
  const [doc, setDoc] = useState<DocumentDetail | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState<"all" | number>("all");

  async function load() {
    const [detail, controlRows, events] = await Promise.all([
      api<DocumentDetail>(`/api/v1/documents/${params.id}`),
      api<Control[]>("/api/v1/controls"),
      api<Audit[]>(`/api/v1/audit?entity_type=document&entity_id=${params.id}`),
    ]);
    setDoc(detail);
    setControls(controlRows);
    setAudit(events);
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [params.id]);

  async function onVersion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const file = new FormData(form).get("file");
    if (!(file instanceof File) || file.size === 0) {
      setError("Choose a file for the new version.");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await upload(`/api/v1/documents/${params.id}/versions`, file);
      form.reset();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Version upload failed");
    } finally {
      setBusy(false);
    }
  }

  async function review(candidateId: string, decision: string, comment?: string, title?: string, statement?: string) {
    setError(null);
    try {
      await api(`/api/v1/candidates/${candidateId}/review`, {
        method: "POST",
        body: JSON.stringify({
          decision,
          comment: comment || null,
          title: title || null,
          statement: statement || null,
        }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Review failed");
    }
  }

  async function mapCandidate(event: FormEvent<HTMLFormElement>, candidateId: string) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const action = String(form.get("action"));
    setError(null);
    try {
      const body: Record<string, unknown> = {
        action,
        rationale: form.get("rationale") || null,
      };
      if (action === "link_existing") {
        body.control_id = form.get("control_id");
      }
      if (action === "propose_new") {
        body.new_control = {
          identifier: form.get("identifier") || null,
          title: form.get("title"),
          objective: form.get("objective"),
          owner: form.get("owner") || "security",
        };
      }
      await api(`/api/v1/candidates/${candidateId}/map-control`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Mapping failed");
    }
  }

  if (!doc) {
    return error ? <ErrorBanner message={error} /> : <LoadingState />;
  }

  const candidates =
    filter === "all" ? doc.candidates : doc.candidates.filter((item) => item.version_number === filter);

  return (
    <div className="stack">
      <PageHeader
        kicker="Document intelligence"
        title={doc.title}
        lede="Processing status is recorded per version. Extracted items remain candidates until a human approves them. Legal compliance is never claimed from extraction."
        crumbs={[{ href: "/documents", label: "Documents" }, { label: doc.title }]}
      />
      <p>
        Status: <StatusPill value={doc.status} /> · Version {doc.current_version}
      </p>
      {doc.failure_reason && <ErrorBanner message={doc.failure_reason} />}
      <ErrorBanner message={error} />

      <section>
        <h2>Versions</h2>
        <form className="form" onSubmit={onVersion}>
          <label>
            New version
            <input name="file" type="file" accept=".pdf,.docx,.txt,.md,text/plain,text/markdown,application/pdf" required />
          </label>
          <button className="btn" type="submit" disabled={busy}>
            {busy ? "Processing…" : "Upload version"}
          </button>
        </form>
        <table className="table">
          <thead>
            <tr>
              <th>Ver</th>
              <th>File</th>
              <th>Hash</th>
              <th>Extraction</th>
            </tr>
          </thead>
          <tbody>
            {doc.versions.map((item) => (
              <tr key={item.id}>
                <td>{item.version_number}</td>
                <td>
                  {item.original_filename} ({item.media_kind}
                  {item.page_count ? `, ${item.page_count}p` : ""})
                </td>
                <td>
                  <code>{item.content_hash.slice(0, 12)}…</code>
                </td>
                <td>
                  <StatusPill value={item.extraction_status} />
                  {item.extraction_provider ? ` · ${item.extraction_provider}/${item.extraction_model}` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Candidates</h2>
        <label>
          Show version{" "}
          <select value={filter} onChange={(event) => setFilter(event.target.value === "all" ? "all" : Number(event.target.value))}>
            <option value="all">all</option>
            {doc.versions.map((item) => (
              <option key={item.id} value={item.version_number}>
                {item.version_number}
              </option>
            ))}
          </select>
        </label>
        {candidates.length === 0 ? (
          <EmptyState title="No candidates in this view" detail="Upload a version or choose another version filter." />
        ) : null}
        {candidates.map((item) => (
          <article className="card" key={item.id} style={{ marginTop: "1rem" }}>
            <p className="kicker">
              {item.candidate_type} · v{item.version_number} · {Math.round(item.confidence * 100)}%
            </p>
            <h2>{item.title}</h2>
            <p>{item.statement}</p>
            <p className="lede">
              Source: {item.provenance.section || "document"}
              {item.provenance.page ? ` · page ${item.provenance.page}` : ""} · hash {item.provenance.content_hash.slice(0, 12)}…
              · {item.provenance.extraction_method}/{item.provenance.extraction_model}
            </p>
            <blockquote className="principle">{item.provenance.quote}</blockquote>
            <p>
              Review: <StatusPill value={item.review_status} />
              {item.authoritative_requirement_id ? (
                <>
                  {" "}
                  · <Link href={`/requirements/${item.authoritative_requirement_id}`}>requirement</Link>
                </>
              ) : null}
              {item.authoritative_control_id ? (
                <>
                  {" "}
                  · <Link href={`/controls/${item.authoritative_control_id}`}>control</Link>
                </>
              ) : null}
            </p>
            {(item.review_status === "pending" || item.review_status === "needs_revision") && (
              <form
                className="form"
                onSubmit={(event) => {
                  event.preventDefault();
                  const form = new FormData(event.currentTarget);
                  void review(
                    item.id,
                    String(form.get("decision")),
                    String(form.get("comment") || ""),
                    String(form.get("title") || item.title),
                    String(form.get("statement") || item.statement),
                  );
                }}
              >
                <label>
                  Title
                  <input name="title" defaultValue={item.title} maxLength={200} />
                </label>
                <label>
                  Statement
                  <textarea name="statement" defaultValue={item.statement} maxLength={20000} />
                </label>
                <label>
                  Decision
                  <select name="decision" defaultValue="approved">
                    <option value="approved">approved</option>
                    <option value="rejected">rejected</option>
                    <option value="needs_revision">needs_revision</option>
                  </select>
                </label>
                <label>
                  Comment
                  <textarea name="comment" />
                </label>
                <button className="btn" type="submit">
                  Record review
                </button>
              </form>
            )}
            {item.review_status === "approved" && item.candidate_type === "requirement" && (
              <form className="form" onSubmit={(event) => void mapCandidate(event, item.id)}>
                <label>
                  Map to control
                  <select name="action" defaultValue="link_existing">
                    <option value="link_existing">link existing</option>
                    <option value="propose_new">propose new</option>
                    <option value="reject">reject mapping</option>
                  </select>
                </label>
                <label>
                  Existing control
                  <select name="control_id">
                    {controls.map((control) => (
                      <option key={control.id} value={control.id}>
                        {control.identifier} · {control.title}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  New identifier
                  <input name="identifier" maxLength={32} placeholder="DOC-…" />
                </label>
                <label>
                  New title
                  <input name="title" maxLength={200} defaultValue={item.title} />
                </label>
                <label>
                  New objective
                  <textarea name="objective" defaultValue={item.statement} />
                </label>
                <label>
                  Owner
                  <input name="owner" defaultValue="security" />
                </label>
                <label>
                  Rationale
                  <textarea name="rationale" />
                </label>
                <button className="btn" type="submit">
                  Record mapping
                </button>
              </form>
            )}
          </article>
        ))}
      </section>

      <section>
        <h2>Audit</h2>
        <table className="table">
          <thead>
            <tr>
              <th>Action</th>
              <th>Actor</th>
              <th>When</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((item) => (
              <tr key={item.id}>
                <td>{item.action}</td>
                <td>{item.actor}</td>
                <td>{formatWhen(item.at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
