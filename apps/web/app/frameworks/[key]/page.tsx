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

type Item = {
  id: string;
  reference_code: string;
  title: string;
  locator: string | null;
  mapped: boolean;
  coverage_status: string;
  control_count: number;
};

type Framework = {
  key: string;
  title: string;
  locator: string;
  catalog_complete: boolean;
  legal_compliance_claim: boolean;
  items: Item[];
};

export default function FrameworkDetailPage() {
  const params = useParams<{ key: string }>();
  const [data, setData] = useState<Framework | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Framework>(`/api/v1/frameworks/${params.key}`)
      .then(setData)
      .catch((err: Error) => setError(err.message));
  }, [params.key]);

  if (!data) {
    return error ? <ErrorBanner message={error} /> : <LoadingState label="Loading framework…" />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Framework assurance"
        title={data.title}
        lede="Each item is a curated pointer with a public locator. Coverage follows mapped controls. Catalog is incomplete. Not a legal compliance result."
        crumbs={[
          { href: "/frameworks", label: "Frameworks" },
          { label: data.title },
        ]}
      />
      <ErrorBanner message={error} />
      <p className="muted">
        Source <a href={data.locator}>{data.locator}</a> · complete {String(data.catalog_complete)} · legal claim{" "}
        {String(data.legal_compliance_claim)}
      </p>
      {data.items.length === 0 ? (
        <EmptyState title="No items" detail="Load the curated catalog from Frameworks." />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Code</th>
              <th>Title</th>
              <th>Mapped</th>
              <th>Coverage</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((item) => (
              <tr key={item.id}>
                <td>
                  <Link href={`/frameworks/${data.key}/${encodeURIComponent(item.reference_code)}`}>
                    {item.reference_code}
                  </Link>
                </td>
                <td>{item.title}</td>
                <td>{item.mapped ? item.control_count : "no"}</td>
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
