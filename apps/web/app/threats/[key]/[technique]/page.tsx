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
type System = { id: string; name: string; display_name?: string; environment: string };
type Finding = { id: string; title: string; status: string; severity: string };
type Test = { scenario_key: string; rationale: string; executes: boolean };

type Item = {
  key: string;
  title: string;
  statement: string;
  locator: string;
  source_kind: string;
  catalog_version: string;
  threat_key: string;
  threat_title: string;
  mapped: boolean;
  coverage_status: string;
  informational_only: boolean;
  legal_compliance_claim: boolean;
  catalog_complete: boolean;
  affected_capability?: string;
  controls: Control[];
  systems: System[];
  findings: Finding[];
  suggested_tests: Test[];
  framework_reference: { framework_key: string; reference_code: string; locator: string | null } | null;
};

export default function TechniquePage() {
  const params = useParams<{ key: string; technique: string }>();
  const techniqueKey = decodeURIComponent(params.technique);
  const [item, setItem] = useState<Item | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const [detail, rows] = await Promise.all([
      api<Item>(`/api/v1/threats/${params.key}/techniques/${encodeURIComponent(techniqueKey)}`),
      api<Control[]>("/api/v1/controls?scope=showcase"),
    ]);
    setItem(detail);
    setControls(rows);
  }

  useEffect(() => {
    load().catch((err: Error) => setError(err.message));
  }, [params.key, techniqueKey]);

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
      await api(`/api/v1/threats/${item.threat_key}/techniques/${item.key}/control-mappings`, {
        method: "POST",
        body: JSON.stringify({
          control_id: controlId,
          note: "Informational mapping. Does not change assurance status.",
        }),
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Map failed");
    }
  }

  if (!item) {
    return error ? <ErrorBanner message={error} /> : <LoadingState label="Loading technique…" />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker={item.threat_title}
        title={item.title}
        lede="Informational technique with source provenance. Mapping a control does not declare legal compliance and does not run a test."
        crumbs={[
          { href: "/threats", label: "Threats" },
          { href: `/threats/${params.key}`, label: item.threat_title },
          { label: item.key },
        ]}
      />
      <ErrorBanner message={error} />
      <p>{item.statement}</p>
      <p className="muted">
        Locator <a href={item.locator}>{item.locator}</a> · {item.source_kind} · catalog {item.catalog_version} · capability{" "}
        {item.affected_capability || "unknown"} · complete{" "}
        {String(item.catalog_complete)} · informational {String(item.informational_only)} · legal claim{" "}
        {String(item.legal_compliance_claim)}
      </p>
      {item.framework_reference && (
        <p className="muted">
          Framework pointer{" "}
          <Link href={`/frameworks/${item.framework_reference.framework_key}/${item.framework_reference.reference_code}`}>
            {item.framework_reference.framework_key}:{item.framework_reference.reference_code}
          </Link>
        </p>
      )}
      <p>
        Coverage <StatusPill value={item.coverage_status} tone={assuranceTone(item.coverage_status)} />
      </p>
      <section>
        <h2>Affected controls</h2>
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
      <section>
        <h2>Affected AI systems</h2>
        {item.systems.length === 0 ? (
          <EmptyState title="No linked systems" detail="Systems appear when mapped controls have runs, evidence, or the labelled demo." />
        ) : (
          <ul>
            {item.systems.map((system) => (
              <li key={system.id}>
                <Link href={`/systems/${system.id}`}>
                  {system.display_name || system.name} ({system.environment})
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h2>Suggested tests</h2>
        {item.suggested_tests.length === 0 ? (
          <EmptyState title="No candidate tests" detail="Suggestions point at existing catalog scenarios. They never auto-execute." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Rationale</th>
              </tr>
            </thead>
            <tbody>
              {item.suggested_tests.map((test) => (
                <tr key={test.scenario_key}>
                  <td>
                    <Link href="/assurance">{test.scenario_key}</Link>
                    <div className="muted">executes {String(test.executes)}</div>
                  </td>
                  <td>{test.rationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section>
        <h2>Open findings</h2>
        {item.findings.length === 0 ? (
          <EmptyState title="No open findings" detail="Findings appear when mapped controls have unresolved assurance results." />
        ) : (
          <ul>
            {item.findings.map((finding) => (
              <li key={finding.id}>
                <Link href={`/findings/${finding.id}`}>
                  {finding.title} ({finding.status})
                </Link>
              </li>
            ))}
          </ul>
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
