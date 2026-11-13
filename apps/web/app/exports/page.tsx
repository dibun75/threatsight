"use client";

import { useState } from "react";

import { ConfirmButton } from "@/components/ConfirmButton";
import { ErrorBanner } from "@/components/ErrorBanner";
import { PageHeader } from "@/components/PageHeader";

const EXPORTS = [
  { path: "/api/v1/exports/findings.json", filename: "findings.json", label: "Findings JSON" },
  { path: "/api/v1/exports/findings.csv", filename: "findings.csv", label: "Findings CSV" },
  { path: "/api/v1/exports/evidence.json", filename: "evidence.json", label: "Evidence JSON" },
  { path: "/api/v1/exports/controls.json", filename: "controls.json", label: "Controls JSON" },
  { path: "/api/v1/exports/audit.json", filename: "audit.json", label: "Audit JSON" },
  { path: "/api/v1/exports/audit.csv", filename: "audit.csv", label: "Audit CSV" },
  { path: "/api/v1/exports/grc-bundle.json", filename: "grc-bundle.json", label: "GRC exchange bundle" },
  { path: "/api/v1/exports/control-matrix.json", filename: "control-matrix.json", label: "Control matrix JSON" },
  { path: "/api/v1/exports/control-matrix.csv", filename: "control-matrix.csv", label: "Control matrix CSV" },
];

async function download(path: string, filename: string) {
  const response = await fetch(path, {
  });
  if (!response.ok) {
    throw new Error((await response.text()) || `${response.status} ${response.statusText}`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export default function ExportsPage() {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function run(path: string, filename: string) {
    setError(null);
    setBusy(filename);
    try {
      await download(path, filename);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Enterprise operations"
        title="Assurance exports"
        lede="Download findings, evidence, controls, audit events, a Saidot-class GRC exchange bundle, or the control matrix. Exports never claim legal compliance and are not a live GRC connector."
      />
      <ErrorBanner message={error} />
      <table className="table">
        <thead>
          <tr>
            <th>Export</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {EXPORTS.map((item) => (
            <tr key={item.path}>
              <td>
                {item.label}
                <div className="muted">{item.path}</div>
              </td>
              <td>
                <ConfirmButton
                  label={`Download ${item.filename}`}
                  confirmLabel={`Confirm ${item.filename}`}
                  disabled={busy !== null}
                  onConfirm={() => void run(item.path, item.filename)}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
