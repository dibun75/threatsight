"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { TruthMark } from "@/components/TruthMark";
import { ApiError, api, errorKind } from "@/lib/api";
import { JOURNEYS } from "@/lib/vocabulary";
import { formatWhen } from "@/lib/time";

type Dashboard = {
  scope?: string;
  synthetic_demo_present?: boolean;
  systems?: { count: number; provenance?: { last_updated?: string | null } };
  controls?: { count: number; provenance?: { last_updated?: string | null } };
  findings?: { open: number; provenance?: { last_updated?: string | null } };
};
type RadarPage = { total: number; items: Array<{ id: string; title: string; published_at: string | null; cves: string[]; relevance: { level: string } }> };
type Snapshot = { completed_at: string | null; node_count: number; limitations: string[] };
type Run = { completed_at: string | null; ruleset_version: string; limitations: string[]; match_count?: number; result_count?: number };
type Service = { id: string; label: string; source_key: string; maturity: string; freshness: string };

export function Overview() {
  const [loading, setLoading] = useState(true);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [radar, setRadar] = useState<RadarPage | null>(null);
  const [snapshot, setSnapshot] = useState<Snapshot | "none" | "down">("none");
  const [matches, setMatches] = useState<Run | "none" | "down">("none");
  const [analysis, setAnalysis] = useState<Run | "none" | "down">("none");
  const [services, setServices] = useState<Service[] | "none">("none");
  const [error, setError] = useState("");

  useEffect(() => {
    document.title = "Overview — ThreatSight";
    const controller = new AbortController();
    const signal = controller.signal;
    Promise.all([
      api<Dashboard>("/api/v1/dashboard", { signal }).then(setDashboard).catch(() => setError("Assurance counts are unavailable.")),
      api<RadarPage>("/api/v1/radar/events?limit=5&sort=published_at&direction=desc", { signal }).then(setRadar).catch(() => setRadar(null)),
      api<Snapshot>("/api/v1/graph/snapshots/current", { signal }).then(setSnapshot).catch((error: unknown) => setSnapshot(error instanceof ApiError && error.status === 404 ? "none" : "down")),
      api<Run>("/api/v1/correlation/current", { signal }).then(setMatches).catch((error: unknown) => setMatches(error instanceof ApiError && error.status === 404 ? "none" : "down")),
      api<Run>("/api/v1/analysis/current", { signal }).then(setAnalysis).catch((error: unknown) => setAnalysis(error instanceof ApiError && error.status === 404 ? "none" : "down")),
      api<Service[]>("/api/v1/graph/services?limit=20", { signal }).then(setServices).catch(() => setServices("none")),
    ]).finally(() => setLoading(false));
    return () => controller.abort();
  }, []);

  const scope = snapshot === "none" || snapshot === "down" ? "No completed exposure snapshot in this workspace" : `${snapshot.node_count} graph nodes`;
  const collected = snapshot !== "none" && snapshot !== "down" ? formatWhen(snapshot.completed_at) : "Not collected";

  return (
    <>
      <PageHeader
        kicker="Continuous hybrid security readiness"
        title="Know what matters. Prove you are ready."
        lede="ThreatSight connects threat intelligence to cloud, identities, firewalls, VPNs, and critical services, then shows what is relevant, what remains uncertain, and which controls require verification."
      />
      {loading ? <LoadingState label="Loading the workspace summary" /> : null}
      {error ? <ErrorBanner message={error} /> : null}
      {loading ? null : <>
      <section aria-labelledby="readiness">
        <h2 id="readiness">Readiness summary</h2>
        <p className="section-note">Scope: this signed-in workspace. Collection time: {collected}. There is no combined score.</p>
        <p>{scope}. {snapshot === "down" ? "The exposure service did not respond." : null}</p>
        <p>
          <TruthMark value={dashboard?.synthetic_demo_present ? "synthetic" : "unknown"} />{" "}
          <TruthMark value={snapshot === "none" ? "unknown" : "fixture_tested"} />
        </p>
      </section>
      <section aria-labelledby="changed">
        <h2 id="changed">What changed</h2>
        {radar ? (
          <>
            <p className="section-note">{radar.total} Radar events in the current filter. Showing the latest {radar.items.length}. This is published reporting, not a customer incident.</p>
            <ul className="record-list">
              {radar.items.map((item) => (
                <li className="record" key={item.id}>
                  <h3>{item.title}</h3>
                  <p>{item.relevance.level} relevance · {formatWhen(item.published_at)}</p>
                  {item.cves[0] ? <Link href={`/exposure/matches?cve=${encodeURIComponent(item.cves[0])}`}>Candidate matches for {item.cves[0]}</Link> : <p>No CVE on this event.</p>}
                </li>
              ))}
            </ul>
          </>
        ) : <p>Radar events could not be loaded. {errorKind(new ApiError(503, "")) === "unavailable" ? "The Radar service may be unavailable." : null}</p>}
        <p>{matches === "none" ? "No completed threat-match run." : matches === "down" ? "Threat-match status is unavailable." : `${matches.match_count ?? 0} candidate matches in ruleset ${matches.ruleset_version}, completed ${formatWhen(matches.completed_at)}.`}</p>
        <p>{analysis === "none" ? "No completed path analysis." : analysis === "down" ? "Path analysis is unavailable." : `${analysis.result_count ?? 0} path results in ruleset ${analysis.ruleset_version}. A supported candidate is not packet delivery.`}</p>
      </section>
      <section aria-labelledby="services">
        <h2 id="services">Services needing attention</h2>
        <ul className="record-list">
          {JOURNEYS.map((journey) => {
            const found = Array.isArray(services) ? services.find((item) => item.source_key.includes(journey.key)) : undefined;
            return (
              <li className="record" key={journey.key}>
                <h3>{journey.title}</h3>
                <p>{journey.purpose}</p>
                <TruthMark value="synthetic" /> <TruthMark value="fixture_tested" />
                {found ? <p><Link href={`/exposure/services/${found.id}`}>{found.label}</Link> · {found.freshness}</p> : <p>Not present in the current snapshot. Absence is not a safety conclusion.</p>}
              </li>
            );
          })}
        </ul>
      </section>
      <section aria-labelledby="uncertainty">
        <h2 id="uncertainty">Evidence and uncertainty</h2>
        <p className="section-note">Configured facts are not observed delivery. Synthetic reference connectors are not live-verified.</p>
        <p>{Array.isArray(services) ? `${services.length} business services on this page of the graph.` : "Business services were not loaded."}</p>
        <p><Link href="/exposure">Open exposure overview</Link></p>
      </section>
      <section aria-labelledby="next">
        <h2 id="next">Next actions</h2>
        <ul>
          <li><Link href="/exposure/matches">Review candidate matches</Link></li>
          <li><Link href="/exposure/connectors">Check whether a live connection exists</Link></li>
          <li><Link href="/assurance">Open assurance. Exposure does not change a control verdict.</Link></li>
          <li><Link href="/findings">Open actions already recorded as findings</Link></li>
        </ul>
        {dashboard ? <p>Assurance records in this workspace: {dashboard.systems?.count ?? 0} AI systems ({formatWhen(dashboard.systems?.provenance?.last_updated)}), {dashboard.controls?.count ?? 0} controls ({formatWhen(dashboard.controls?.provenance?.last_updated)}), {dashboard.findings?.open ?? 0} open findings ({formatWhen(dashboard.findings?.provenance?.last_updated)}). Scope: {dashboard.scope || "workspace dashboard"}.</p> : null}
      </section>
      </>}
    </>
  );
}
