"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { ScopeToggle } from "@/components/ScopeToggle";
import { api } from "@/lib/api";
import type { RecordScope } from "@/lib/scope";
import { withScope } from "@/lib/scope";
import { ASSURANCE_STATUSES, assuranceTone, verdictTone } from "@/lib/status";
import { presentedValue } from "@/lib/vocabulary";

type Control = {
  id: string;
  identifier: string;
  title: string;
  owner: string;
  assurance_status: string;
  latest_verdict: string | null;
  severity: string | null;
  version: number;
};

export default function ControlsPage() {
  const [items, setItems] = useState<Control[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [verdict, setVerdict] = useState("");
  const [scope, setScope] = useState<RecordScope>("showcase");
  const [canCreate, setCanCreate] = useState(false);

  async function load(nextQ = q, nextStatus = status, nextVerdict = verdict) {
    const params = new URLSearchParams();
    if (nextQ.trim()) {
      params.set("q", nextQ.trim());
    }
    if (nextStatus) {
      params.set("assurance_status", nextStatus);
    }
    if (nextVerdict) {
      params.set("latest_verdict", nextVerdict);
    }
    const suffix = params.toString() ? `?${params}` : "";
    setItems(await api<Control[]>(withScope(`/api/v1/controls${suffix}`, scope)));
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [scope]);

  useEffect(() => {
    api<{ role: string }>("/api/v1/radar/workspace")
      .then((session) => setCanCreate(session.role !== "viewer"))
      .catch(() => setCanCreate(false));
  }, []);

  async function onFilter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    try {
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Filter failed");
    }
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError(null);
    try {
      await api("/api/v1/controls", {
        method: "POST",
        body: JSON.stringify({
          identifier: form.get("identifier"),
          title: form.get("title"),
          objective: form.get("objective"),
          owner: form.get("owner"),
          severity: form.get("severity") || null,
          assurance_status: "EVIDENCE_REQUIRED",
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
        kicker="Control library"
        title="Controls"
        lede="Which controls protect a critical service, and whether the latest evidence still holds. A recorded pass is not a compliance certificate."
        actions={<ScopeToggle value={scope} onChange={setScope} />}
      />
      <details>
        <summary>Customer ordering authorization example</summary>
        <p>One synthetic control protects Customer ordering. A failed authorization test, the recorded impact, the change, and the later retest stay on that control. Visitors cannot run the test.</p>
      </details>
      <form className="toolbar" onSubmit={onFilter}>
        <label>
          Search
          <input value={q} onChange={(event) => setQ(event.target.value)} placeholder="CTRL-002 or title" />
        </label>
        <label>
          Assurance
          <select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">any</option>
            {ASSURANCE_STATUSES.map((item) => (
              <option key={item} value={item}>
                {presentedValue(item)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Verdict
          <select value={verdict} onChange={(event) => setVerdict(event.target.value)}>
            <option value="">any</option>
            <option value="PASS">{presentedValue("PASS")}</option>
            <option value="FAIL">{presentedValue("FAIL")}</option>
            <option value="INCONCLUSIVE">{presentedValue("INCONCLUSIVE")}</option>
          </select>
        </label>
        <button className="btn" type="submit">
          Apply
        </button>
      </form>
      {canCreate ? <form className="form" onSubmit={onSubmit}>
        <label>
          Identifier
          <input name="identifier" required pattern="^[A-Z][A-Z0-9_-]{1,31}$" placeholder="CTRL-002" />
        </label>
        <label>
          Title
          <input name="title" required maxLength={200} />
        </label>
        <label>
          Objective
          <textarea name="objective" required maxLength={20000} />
        </label>
        <label>
          Owner
          <input name="owner" required maxLength={200} />
        </label>
        <label>
          Severity
          <select name="severity" defaultValue="high">
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
        </label>
        <button className="btn" type="submit">
          Create control
        </button>
      </form> : null}
      <ErrorBanner message={error} />
      {!items ? (
        <LoadingState />
      ) : items.length === 0 ? (
        <EmptyState title="No matching controls" detail="Open Showcase to load labelled CTRL-002, or clear filters." />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Assurance</th>
              <th>Verdict</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <Link href={`/controls/${item.id}`}>{item.identifier}</Link>
                </td>
                <td>{item.title}</td>
                <td>
                  <StatusPill value={presentedValue(item.assurance_status)} tone={assuranceTone(item.assurance_status)} />
                </td>
                <td>
                  {item.latest_verdict ? (
                    <StatusPill value={presentedValue(item.latest_verdict)} tone={verdictTone(item.latest_verdict)} />
                  ) : (
                    "—"
                  )}
                </td>
                <td>{item.severity || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
