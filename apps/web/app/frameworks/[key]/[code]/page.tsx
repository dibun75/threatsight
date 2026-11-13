"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { useParams } from "next/navigation";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";
import { assuranceTone } from "@/lib/status";

type Control = { id: string; identifier: string; title: string; assurance_status: string };

type Item = {
  id: string;
  framework_key: string;
  reference_code: string;
  title: string;
  statement: string | null;
  locator: string | null;
  source_kind: string | null;
  catalog_version: string | null;
  mapped: boolean;
  coverage_status: string;
  informational_only: boolean;
  legal_compliance_claim: boolean;
  catalog_complete: boolean;
  controls: Control[];
};

export default function FrameworkItemPage() {
  const params = useParams<{ key: string; code: string }>();
  const code = decodeURIComponent(params.code);
  const [item, setItem] = useState<Item | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const [detail, rows] = await Promise.all([
      api<Item>(`/api/v1/frameworks/${params.key}/items/${encodeURIComponent(code)}`),
      api<Control[]>("/api/v1/controls"),
    ]);
    setItem(detail);
    setControls(rows);
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [params.key, code]);

  async function onMap(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!item) {
      return;
    }
    const controlId = String(new FormData(event.currentTarget).get("control_id") || "");
    if (!controlId) {
      setError("Choose a control.");
      return;
    }
    setError(null);
    try {
      await api(`/api/v1/controls/${controlId}/framework-mappings`, {
        method: "POST",
        body: JSON.stringify({
          framework_reference_id: item.id,
          note: "Informational mapping. Not a legal conclusion.",
        }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Map failed");
    }
  }

  if (!item) {
    return error ? <ErrorBanner message={error} /> : <LoadingState label="Loading item…" />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker={item.framework_key}
        title={`${item.reference_code} — ${item.title}`}
        lede="Informational framework pointer with source provenance. Mapping a control does not declare legal compliance."
        crumbs={[
          { href: "/frameworks", label: "Frameworks" },
          { href: `/frameworks/${params.key}`, label: params.key },
          { label: item.reference_code },
        ]}
      />
      <ErrorBanner message={error} />
      <p>{item.statement}</p>
      <p className="muted">
        Locator {item.locator ? <a href={item.locator}>{item.locator}</a> : "—"} · {item.source_kind} · catalog{" "}
        {item.catalog_version} · complete {String(item.catalog_complete)} · informational {String(item.informational_only)}{" "}
        · legal claim {String(item.legal_compliance_claim)}
      </p>
      <p>
        Coverage <StatusPill value={item.coverage_status} tone={assuranceTone(item.coverage_status)} />
      </p>
      <section>
        <h2>Mapped controls</h2>
        {item.controls.length === 0 ? (
          <EmptyState title="No mapped controls" detail="Map an existing control. Coverage stays EVIDENCE_REQUIRED until then." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Control</th>
                <th>Assurance</th>
              </tr>
            </thead>
            <tbody>
              {item.controls.map((control) => (
                <tr key={control.id}>
                  <td>
                    <Link href={`/controls/${control.id}`}>
                      {control.identifier} — {control.title}
                    </Link>
                  </td>
                  <td>
                    <StatusPill value={control.assurance_status} tone={assuranceTone(control.assurance_status)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <form className="form" onSubmit={(event) => void onMap(event)}>
        <label>
          Map control
          <select name="control_id" required>
            <option value="">Select…</option>
            {controls.map((control) => (
              <option key={control.id} value={control.id}>
                {control.identifier} — {control.title}
              </option>
            ))}
          </select>
        </label>
        <button className="btn" type="submit">
          Map informationally
        </button>
      </form>
    </div>
  );
}
