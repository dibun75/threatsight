"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";
import { assuranceTone } from "@/lib/status";

type Technique = {
  key: string;
  title: string;
  locator: string;
  mapped: boolean;
  coverage_status: string;
  control_count: number;
  suggested_test_count: number;
};

type Threat = {
  key: string;
  title: string;
  statement: string;
  catalog_complete: boolean;
  legal_compliance_claim: boolean;
  techniques: Technique[];
};

export default function ThreatDetailPage() {
  const params = useParams<{ key: string }>();
  const [data, setData] = useState<Threat | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Threat>(`/api/v1/threats/${params.key}`)
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, [params.key]);

  if (!data) {
    return error ? <ErrorBanner message={error} /> : <LoadingState label="Loading threat…" />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Threat intelligence"
        title={data.title}
        lede="Normalized techniques with public locators. Coverage follows mapped controls. Catalog is incomplete. Not a legal compliance result."
        crumbs={[
          { href: "/threats", label: "Threats" },
          { label: data.title },
        ]}
      />
      <ErrorBanner message={error} />
      <p>{data.statement}</p>
      <p className="muted">
        complete {String(data.catalog_complete)} · legal claim {String(data.legal_compliance_claim)}
      </p>
      {data.techniques.length === 0 ? (
        <EmptyState title="No techniques" detail="Load the curated catalog from Intelligence." />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Technique</th>
              <th>Mapped</th>
              <th>Tests</th>
              <th>Coverage</th>
            </tr>
          </thead>
          <tbody>
            {data.techniques.map((item) => (
              <tr key={item.key}>
                <td>
                  <Link href={`/threats/${data.key}/${item.key}`}>{item.title}</Link>
                  <div className="muted">{item.key}</div>
                </td>
                <td>{item.mapped ? item.control_count : "no"}</td>
                <td>{item.suggested_test_count}</td>
                <td>
                  <StatusPill value={item.coverage_status} tone={assuranceTone(item.coverage_status)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
