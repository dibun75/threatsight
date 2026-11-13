"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";

import { HeroMap } from "@/components/command/HeroMap";
import { TelemetryBanner, useActivity } from "@/components/command/TelemetryBanner";
import { ThreatObservatory } from "@/components/command/ThreatObservatory";
import { api } from "@/lib/api";
import { humanize } from "@/lib/humanize";
import { threatView } from "@/lib/experience";
import { maturityStatement, presentedValue } from "@/lib/vocabulary";

type Advisory = { id: string; title: string; vendor: string; maturity: string; kev_listed: boolean; epss_score: number | null; priority_reason: string; freshness: string; category?: string };
type Source = { key: string; authority: string; maturity: string; health: string; last_success_at: string | null };
type Cluster = {
  id: string;
  cve: string | null;
  title: string;
  exploitation_state: string;
  exploitation_explanation: string;
  organization_relevance?: string;
  updated_at: string;
};
type IntelSource = {
  source_key: string;
  source_role: string;
  role_label: string;
  enabled: boolean;
  health: string;
  maturity: string;
  token_required: boolean;
  last_success_at: string | null;
  last_attempt_at: string | null;
  last_error_code: string | null;
};

const TABS = [
  ["emerging", "Emerging exploitation"],
  ["advisory", "Advisory activity"],
  ["relevance", "Organization relevance"],
  ["telemetry", "Observed telemetry"],
  ["sources", "Source health"],
] as const;

function Threats() {
  const params = useSearchParams();
  const router = useRouter();
  const selected = threatView(params.get("view"));
  const [view, setView] = useState(selected);
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [intelSources, setIntelSources] = useState<IntelSource[]>([]);
  const [category, setCategory] = useState("all");
  const telemetry = useActivity();
  useEffect(() => setView(selected), [selected]);
  useEffect(() => {
    api<{ items: Advisory[] }>("/api/v1/landscape/advisories?limit=25").then((page) => setAdvisories(page.items)).catch(() => setAdvisories([]));
    api<{ items: Source[] }>("/api/v1/landscape/sources").then((page) => setSources(page.items)).catch(() => setSources([]));
    api<{ items: Cluster[] }>("/api/v1/multisource/clusters?limit=25").then((page) => setClusters(page.items)).catch(() => setClusters([]));
    api<{ items: IntelSource[] }>("/api/v1/multisource/sources").then((page) => setIntelSources(page.items)).catch(() => setIntelSources([]));
  }, []);
  const categories = [...new Set(advisories.map((item) => item.vendor))].sort();
  const shown = advisories.filter((item) => category === "all" || item.vendor === category).slice(0, view === "relevance" ? 3 : 8);
  function selectView(value: typeof TABS[number][0]) {
    setView(value);
    router.push(`/threats?view=${value}`, { scroll: false });
  }
  return (
    <article className="stack threat-activity">
      <p className="kicker">Threat activity</p>
      <h1>{TABS.find((item) => item[0] === view)?.[1]}</h1>
      <div className="metric-switch" role="tablist" aria-label="Threat activity">
        {TABS.map(([value, label]) => (
          <button key={value} className="btn secondary" type="button" role="tab" aria-selected={view === value} onClick={() => selectView(value)}>{label}</button>
        ))}
      </div>
      {view === "emerging" ? (
        <section>
          <p>Purpose: show multi-source exploitation clusters. Vendor facts, researcher observations, media discovery, CISA KEV, and EPSS stay separate. This is not a news reader and not proof of customer impact.</p>
          <div className="table-scroll" tabIndex={0}>
            <table>
              <caption>Emerging exploitation clusters.</caption>
              <thead>
                <tr>
                  <th scope="col">Change / CVE</th>
                  <th scope="col">Exploitation evidence</th>
                  <th scope="col">Organization relevance</th>
                  <th scope="col">Required action</th>
                </tr>
              </thead>
              <tbody>
                {clusters.map((item) => (
                  <tr key={item.id}>
                    <th scope="row">
                      <Link href={`/threats/emerging/${item.id}`}>{item.cve || item.title}</Link>
                      <div>{item.title}</div>
                    </th>
                    <td>{humanize(item.exploitation_state)}. {item.exploitation_explanation}</td>
                    <td>{item.organization_relevance || "No stored match"}</td>
                    <td>{item.organization_relevance?.includes("Synthetic product") ? "Manual verification (approval required)" : "Monitor sources"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {clusters.length === 0 ? <p className="empty-state">No exploitation cluster is stored yet.</p> : null}
          <h2>Multi-source collector health</h2>
          <div className="table-scroll" tabIndex={0}>
            <table>
              <caption>Multi-source collector health.</caption>
              <thead>
                <tr>
                  <th scope="col">Source</th>
                  <th scope="col">Role</th>
                  <th scope="col">Enabled</th>
                  <th scope="col">Health</th>
                  <th scope="col">Last success</th>
                </tr>
              </thead>
              <tbody>
                {intelSources.map((item) => (
                  <tr key={item.source_key}>
                    <th scope="row">{item.source_key}{item.token_required ? " (token required)" : ""}</th>
                    <td>{item.role_label}</td>
                    <td>{item.enabled ? "Enabled" : "Disabled"}</td>
                    <td>{presentedValue(item.health)}</td>
                    <td>{item.last_success_at ? "Recorded" : "None yet"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>Next step: open a cluster to inspect vendor facts, observations, media, KEV, EPSS, and unknowns separately.</p>
        </section>
      ) : null}
      {view === "advisory" ? (
        <section>
          <p>Purpose: show live public advisory geography and recent advisory records. Source: landscape collectors. This is not observed attack telemetry.</p>
          <label className="form">Advisory source
            <select value={category} onChange={(event) => setCategory(event.target.value)}>
              <option value="all">All sources in this page</option>
              {categories.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </label>
          <HeroMap />
          <div className="table-scroll" tabIndex={0}>
            <table>
              <caption>Advisory activity records.</caption>
              <thead><tr><th scope="col">Advisory</th><th scope="col">Source</th><th scope="col">Freshness</th><th scope="col">KEV</th><th scope="col">EPSS</th></tr></thead>
              <tbody>
                {shown.map((item) => (
                  <tr key={item.id}>
                    <th scope="row"><Link href={`/threats/advisories/${item.id}`}>{item.title}</Link></th>
                    <td>{item.vendor}. {presentedValue(item.maturity)}</td>
                    <td>{item.freshness}</td>
                    <td>{item.kev_listed ? "Listed" : "Not listed"}</td>
                    <td>{item.epss_score ?? "Not supplied"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>Next step: open an advisory, then compare it with organization relevance.</p>
        </section>
      ) : null}
      {view === "relevance" ? (
        <section>
          <p>Purpose: relate live public advisories to the synthetic enterprise. A match is a candidate, not confirmed customer exposure.</p>
          {shown.map((item) => (
            <article className="service-card" key={item.id}>
              <p className="state-badge synthetic" title={maturityStatement(item.maturity)}>Synthetic</p>
              <h2><Link href={`/threats/advisories/${item.id}`}>{item.title}</Link></h2>
              <p>{item.vendor} · {item.freshness} · KEV {item.kev_listed ? "listed" : "not listed"} · EPSS {item.epss_score ?? "not supplied"}.</p>
              <p>{item.priority_reason}</p>
            </article>
          ))}
          {shown.length === 0 ? <p className="empty-state">No advisory is available for this filter.</p> : null}
          <p>Next step: open the service named by the relevance note.</p>
        </section>
      ) : null}
      {view === "telemetry" ? (
        <section aria-label="Observed telemetry">
          <TelemetryBanner state={telemetry.state} activity={telemetry.activity} />
          <ThreatObservatory />
        </section>
      ) : null}
      {view === "sources" ? (
        <section>
          <p>Purpose: show collector health. This is not an advisory total and it is not attack telemetry.</p>
          <div className="table-scroll" tabIndex={0}>
            <table>
              <caption>Source health.</caption>
              <thead><tr><th scope="col">Source</th><th scope="col">Maturity</th><th scope="col">Health</th><th scope="col">Last success</th></tr></thead>
              <tbody>
                {sources.map((item) => (
                  <tr key={item.key}><th scope="row">{item.authority}</th><td>{presentedValue(item.maturity)}</td><td>{presentedValue(item.health)}</td><td>{item.last_success_at ? "Recorded" : "None yet"}</td></tr>
                ))}
                {intelSources.map((item) => (
                  <tr key={item.source_key}>
                    <th scope="row">{item.source_key} ({item.role_label})</th>
                    <td>{presentedValue(item.maturity)}</td>
                    <td>{presentedValue(item.health)}</td>
                    <td>{item.last_success_at ? "Recorded" : "None yet"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {sources.length === 0 && intelSources.length === 0 ? <p className="empty-state">Source health is unavailable.</p> : null}
          <p>Next step: if a collector has no success time, treat its advisories as unconfirmed.</p>
        </section>
      ) : null}
    </article>
  );
}

export default function ThreatsPage() {
  return <Suspense fallback={<p className="skeleton" aria-busy="true">Loading threat activity.</p>}><Threats /></Suspense>;
}
