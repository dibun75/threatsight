"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Choropleth } from "@/components/landscape/Choropleth";
import { api } from "@/lib/api";

type Geo = { metric: string; included: number; excluded: number; items: { country: string; count: number }[]; does_not_mean: string };
type Advisory = {
  id: string;
  title: string;
  vendor: string;
  maturity: string;
  kev_listed: boolean;
  epss_score: number | null;
  priority_reason: string;
  cves: string[];
  freshness: string;
};
type Source = {
  key: string;
  maturity: string;
  health: string;
  last_status: string;
  authority: string;
  last_success_at: string | null;
  next_attempt_at: string | null;
};
type Matrix = { vendor: string; family: string; advisories: number };
type Summary = {
  stored_total: number;
  included: number;
  excluded_withdrawn: number;
  stale_included: number;
  live_verified_advisories: number;
  fixture_tested: number;
  credential_required: number;
  unsupported: number;
  unknown: number;
};

const METRICS = [
  ["authority_jurisdiction", "Authority jurisdiction"],
  ["affected_jurisdiction", "Explicitly affected jurisdiction"],
  ["national_alert", "National warning"],
  ["advisory_jurisdiction", "Advisory jurisdiction"],
] as const;

export default function LandscapePage() {
  const [metric, setMetric] = useState<string>("authority_jurisdiction");
  const [geo, setGeo] = useState<Geo | null>(null);
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [matrix, setMatrix] = useState<Matrix[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    Promise.all([
      api<Geo>(`/api/v1/landscape/geography?metric=${metric}`),
      api<{ items: Advisory[] }>("/api/v1/landscape/advisories?limit=25"),
      api<{ items: Source[] }>("/api/v1/landscape/sources"),
      api<{ items: Matrix[] }>("/api/v1/landscape/matrix"),
      api<Summary>("/api/v1/landscape/summary"),
    ])
      .then(([geography, advisoryPage, sourcePage, matrixPage, summaryPage]) => {
        if (!active) return;
        setGeo(geography);
        setAdvisories(advisoryPage.items);
        setSources(sourcePage.items);
        setMatrix(matrixPage.items);
        setSummary(summaryPage);
      })
      .catch(() => {
        if (active) setError("The landscape could not be loaded.");
      });
    return () => {
      active = false;
    };
  }, [metric]);

  return (
    <div className="stack">
      <h1>Threat landscape</h1>
      <p>
        Public intelligence is labeled by source maturity. Enterprise assets and services on this page are synthetic.
        A match is evidence to investigate, not confirmed exposure.
      </p>
      {error ? <p role="alert">{error}</p> : null}
      <section>
        <h2>What changed</h2>
        <p>
          {summary
            ? `${summary.stored_total} stored advisories: ${summary.live_verified_advisories} live-verified, ${summary.fixture_tested} validated with reference data, ${summary.credential_required} credential-required, ${summary.unsupported} unsupported, ${summary.unknown} unknown, and ${summary.excluded_withdrawn} withdrawn. Withdrawn advisories stay stored and are left out of the maturity buckets. ${summary.stale_included} stale advisories remain inside their maturity bucket. The page is not globally live.`
            : "Loading source maturity."}{" "}
          {geo ? `This map includes ${geo.included} advisories and excludes ${geo.excluded} withdrawn or stale records. That exclusion does not change the stored advisory total.` : "Loading."}
          {" "}KEV and EPSS stay separate. Geography is the selected jurisdiction role.
        </p>
      </section>
      <section>
        <h2>Jurisdiction heatmap</h2>
        <div className="metric-switch" role="group" aria-label="Heatmap metric">
          {METRICS.map(([value, label]) => (
            <button key={value} type="button" aria-pressed={metric === value} onClick={() => setMetric(value)}>
              {label}
            </button>
          ))}
        </div>
        <p>
          Metric: {metric}. The colour intensity is the count in the table. This is not a live attack map.
        </p>
        <Choropleth items={geo?.items ?? []} mode="advisory" selected="all" onSelect={() => undefined} />
        <div className="table-scroll" tabIndex={0} aria-label="Geography counts. Scroll sideways inside this region if the table is wider than the screen.">
        <table>
          <caption>Same counts as the heatmap. {geo?.does_not_mean}</caption>
          <thead>
            <tr>
              <th scope="col">Code</th>
              <th scope="col">Count</th>
            </tr>
          </thead>
          <tbody>
            {(geo?.items ?? []).map((item) => (
              <tr key={item.country}>
                <th scope="row">{item.country}</th>
                <td>{item.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </section>
      <section>
        <h2>Vendor and product</h2>
        <div className="table-scroll" tabIndex={0} aria-label="Vendor and product counts. Scroll sideways inside this region if the table is wider than the screen.">
        <table>
          <thead>
            <tr>
              <th scope="col">Vendor</th>
              <th scope="col">Family</th>
              <th scope="col">Advisories</th>
            </tr>
          </thead>
          <tbody>
            {matrix.map((item) => (
              <tr key={`${item.vendor}-${item.family}`}>
                <td>{item.vendor}</td>
                <td>{item.family}</td>
                <td>{item.advisories}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </section>
      <section>
        <h2>Investigation order</h2>
        <div className="table-scroll" tabIndex={0} aria-label="Investigation order. Scroll sideways inside this region if the table is wider than the screen.">
        <table>
          <thead>
            <tr>
              <th scope="col">Advisory</th>
              <th scope="col">KEV</th>
              <th scope="col">EPSS</th>
              <th scope="col">Why this order</th>
            </tr>
          </thead>
          <tbody>
            {advisories.map((item) => (
              <tr key={item.id}>
                <td>
                  <Link href={`/landscape/${item.id}`}>{item.title}</Link>
                  <div>{item.maturity}</div>
                </td>
                <td>{item.kev_listed ? "Listed" : "Not listed"}</td>
                <td>{item.epss_score == null ? "Not supplied" : item.epss_score}</td>
                <td>{item.priority_reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </section>
      <section>
        <h2>Source health</h2>
        <p>Source health describes collectors, not the advisory total above.</p>
        <div className="table-scroll" tabIndex={0} aria-label="Source health. Scroll sideways inside this region if the table is wider than the screen.">
        <table>
          <thead>
            <tr>
              <th scope="col">Source</th>
              <th scope="col">Maturity</th>
              <th scope="col">Health</th>
              <th scope="col">Status</th>
              <th scope="col">Last success</th>
              <th scope="col">Next attempt</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((item) => (
              <tr key={item.key}>
                <th scope="row">{item.authority}</th>
                <td>{item.maturity}</td>
                <td>{item.health}</td>
                <td>{item.last_status}</td>
                <td>{item.last_success_at ? new Date(item.last_success_at).toISOString() : "None yet"}</td>
                <td>{item.next_attempt_at ? new Date(item.next_attempt_at).toISOString() : "Not scheduled"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </section>
    </div>
  );
}
