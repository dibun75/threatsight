"use client";

import { useEffect, useState } from "react";

import { ObservatoryStage, type StageSignals } from "@/components/command/ObservatoryStage";
import { Choropleth } from "@/components/landscape/Choropleth";
import { SourceTime } from "@/components/command/SourceTime";
import { api } from "@/lib/api";
import { buildTicker } from "@/lib/observatory-ticker";

type Observation = {
  kind: string;
  indicator: string;
  category: string;
  detail: string;
  reference_url: string;
  confidence: string;
  country_code?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
};
type ThreatFoxItem = { indicator_type: string; indicator: string; port?: number | null; category: string; detail: string; malware_family?: string; threat_type?: string; confidence_score?: number; last_seen?: string | null };
type ThreatFoxFeed = { state: string; connected: boolean; retrieved_at?: string | null; attribution: string; terms_state: string; items: ThreatFoxItem[]; does_not_mean: string };
type AbuseFeed = { state: string; connected: boolean; retrieved_at?: string | null; items: { indicator: string; category: string; detail: string; country_code?: string | null; malware_family?: string; threat_type?: string }[]; countries: { country: string; count: number }[] };
type GreyNoiseResult = { ip: string; status: string; noise?: boolean | null; riot?: boolean | null; classification?: string | null; name?: string | null; provider?: string | null; last_seen?: string | null; message?: string | null; does_not_mean: string };
type Port = { port: number; service?: string | null; detail?: string; rank?: number | null };
type Category = { category: string; count: number };
type Observatory = {
  state: string;
  connected: boolean;
  retrieved_at?: string | null;
  attribution: string;
  terms_state: string;
  items: Observation[];
  categories: Category[];
  ports: Port[];
  countries: { country: string; count: number }[];
  does_not_mean: string;
};

function words(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function ThreatObservatory() {
  const [data, setData] = useState<Observatory | null>(null);
  const [threatfox, setThreatfox] = useState<ThreatFoxFeed | null>(null);
  const [feodo, setFeodo] = useState<AbuseFeed | null>(null);
  const [urlhaus, setUrlhaus] = useState<AbuseFeed | null>(null);
  const [pending, setPending] = useState(true);
  const [scanCountry, setScanCountry] = useState("all");
  const [lookupIp, setLookupIp] = useState("");
  const [greyNoise, setGreyNoise] = useState<GreyNoiseResult | null>(null);
  const [lookupState, setLookupState] = useState<"idle" | "pending" | "error">("idle");
  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      api<Observatory>("/api/v1/telemetry/observations?limit=80", { signal: controller.signal }).then(setData).catch(() => setData(null)),
      api<ThreatFoxFeed>("/api/v1/telemetry/observations/threatfox?limit=30", { signal: controller.signal }).then(setThreatfox).catch(() => setThreatfox(null)),
      api<AbuseFeed>("/api/v1/telemetry/observations/feodo?limit=250", { signal: controller.signal }).then(setFeodo).catch(() => setFeodo(null)),
      api<AbuseFeed>("/api/v1/telemetry/observations/urlhaus?limit=30", { signal: controller.signal }).then(setUrlhaus).catch(() => setUrlhaus(null)),
    ]).finally(() => setPending(false));
    return () => controller.abort();
  }, []);
  async function pollGreyNoise(ip: string) {
    for (let attempt = 0; attempt < 12; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 3000));
      try {
        const result = await api<GreyNoiseResult>(`/api/v1/telemetry/observations/greynoise?ip=${encodeURIComponent(ip)}`);
        setGreyNoise(result);
        if (result.status !== "pending" && result.status !== "running") return;
      } catch {
        if (attempt === 11) setLookupState("error");
      }
    }
  }
  async function lookupGreyNoise(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLookupState("pending");
    try {
      const queued = await api<GreyNoiseResult>("/api/v1/telemetry/observations/greynoise", {
        method: "POST",
        body: JSON.stringify({ ip: lookupIp, refresh: false }),
      });
      setGreyNoise(queued);
      if (queued.status === "pending" || queued.status === "running") {
        void pollGreyNoise(lookupIp);
      }
      setLookupState("idle");
    } catch {
      setLookupState("error");
    }
  }
  const connected = Boolean(data?.connected);
  const malwareConnected = Boolean(threatfox?.connected);
  const liveLayers = 1 + (connected ? 1 : 0) + (malwareConnected ? 1 : 0);
  const observationCount = (data?.categories ?? []).reduce((total, item) => total + item.count, 0);
  const countryCount = (data?.countries ?? []).length;
  const portCount = (data?.ports ?? []).length;
  const feodoConnected = Boolean(feodo?.connected);
  const urlhausConnected = Boolean(urlhaus?.connected);
  const ticker = buildTicker(data?.items ?? [], threatfox?.items ?? [], 32, feodo?.items ?? [], urlhaus?.items ?? []);
  const families = new Map<string, number>();
  for (const item of [...(threatfox?.items ?? []), ...(feodo?.items ?? []), ...(urlhaus?.items ?? [])]) {
    const name = item.malware_family?.trim();
    if (name) families.set(name, (families.get(name) ?? 0) + 1);
  }
  const threats = [...families].map(([name, count]) => ({ name, count })).sort((left, right) => right.count - left.count);
  const signals: StageSignals = { scan: connected ? data?.countries ?? [] : [], c2: feodoConnected ? feodo?.countries ?? [] : [] };
  return (
    <section className="observatory" aria-labelledby="observatory-title">
      <ObservatoryStage signals={signals} feed={ticker} threats={threats} />
      <details className="feed-detail">
        <summary>Feed detail and IP lookup</summary>
      <nav className="observatory-layers" aria-label="Observation layers">
        <a className="is-live" href="#observatory-title"><span>Live</span><strong>L7 routes</strong><small>Cloudflare Radar</small></a>
        <a className={connected ? "is-live" : "is-pending"} href="#signal-stream"><span>{connected ? "Live" : "Pending review"}</span><strong>IP signals</strong><small>SANS ISC / DShield</small></a>
        <a className={malwareConnected ? "is-live" : "is-pending"} href="#malware-stream"><span>{malwareConnected ? "Evaluation live" : "Not enabled"}</span><strong>Malware infrastructure</strong><small>abuse.ch ThreatFox</small></a>
        <a className={feodoConnected ? "is-live" : "is-pending"} href="#observatory-title"><span>{feodoConnected ? "Live" : "Not enabled"}</span><strong>Botnet C2 servers</strong><small>abuse.ch Feodo Tracker</small></a>
        <a className={urlhausConnected ? "is-live" : "is-pending"} href="#observatory-title"><span>{urlhausConnected ? "Live" : "Not enabled"}</span><strong>Malware URLs</strong><small>abuse.ch URLhaus</small></a>
        <a className="is-live" href="/threats?view=emerging"><span>Live</span><strong>Exploitation evidence</strong><small>Vendor · VulnCheck · KEV</small></a>
      </nav>
      <div className="observatory-grid is-single">
        <aside id="signal-stream" className="signal-board" aria-labelledby="signal-title">
          <div className="signal-heading">
            <div><p className="kicker">Independent feed</p><h3 id="signal-title">Observed signals</h3></div>
            <span className={connected ? "signal-live" : "signal-off"}>{pending ? "Loading" : connected ? "Current" : "Not enabled"}</span>
          </div>
          {connected ? (
            <>
              <p className="signal-time">Retrieved <SourceTime value={data?.retrieved_at ?? undefined} /></p>
              <ol className="signal-stream">
                {(data?.items ?? []).slice(0, 14).map((item, index) => (
                  <li key={`${item.indicator}-${index}`}>
                    <span className={`signal-dot signal-${item.category}`} aria-hidden="true" />
                    <div><strong>{item.indicator}</strong><small>{words(item.category)}{item.country_code ? ` · ${item.country_code}` : ""}</small></div>
                    <span>{item.detail || "Source reported"}{item.last_seen ? <> · Last seen <SourceTime value={item.last_seen} /></> : null}</span>
                  </li>
                ))}
              </ol>
            </>
          ) : pending ? (
            <p className="skeleton" aria-busy="true">Loading signals…</p>
          ) : (
            <div className="signal-empty">
              <strong>DShield layer is intentionally off</strong>
              <p>The collector is ready but is not enabled in this deployment. ThreatSight does not substitute synthetic IPs.</p>
            </div>
          )}
          <details>
            <summary>Source and meaning</summary>
            <p>{data?.attribution ?? "SANS Internet Storm Center / DShield"}. Publicly reported observations, not customer traffic.</p>
            <p>{data?.does_not_mean ?? "An IP signal is not attacker attribution or proof that your organization was targeted."}</p>
          </details>
          <div className="ip-enrichment">
            <h4>Investigate one public IP</h4>
            
            <form onSubmit={lookupGreyNoise}>
              <label htmlFor="greynoise-ip">Public IPv4</label>
              <input id="greynoise-ip" inputMode="decimal" value={lookupIp} onChange={(event) => setLookupIp(event.target.value)} placeholder="8.8.8.8" maxLength={15} required />
              <button className="btn" type="submit" disabled={lookupState === "pending"}>{lookupState === "pending" ? "Checking" : "Check IP"}</button>
            </form>
            {lookupState === "error" ? <p role="alert">The lookup was rejected or is unavailable.</p> : null}
            {greyNoise ? <div className="enrichment-result">
              <strong>{greyNoise.ip} - {words(greyNoise.classification || greyNoise.status)}</strong>
              <span>Scanning observed: {greyNoise.noise == null ? "Unknown" : greyNoise.noise ? "Yes" : "No"} · RIOT service: {greyNoise.riot == null ? "Unknown" : greyNoise.riot ? "Yes" : "No"}</span>
              <small>{greyNoise.name || greyNoise.provider || greyNoise.message || "No additional source label"}{greyNoise.last_seen ? <> · Last seen <SourceTime value={greyNoise.last_seen} /></> : null}</small>
              <small>{greyNoise.does_not_mean}</small>
            </div> : null}
          </div>
        </aside>
      </div>
      <div className="observatory-lower">
        <section id="malware-stream" aria-labelledby="malware-title">
          <div className="operations-heading"><div><p className="kicker">Personal evaluation layer</p><h3 id="malware-title">Malware infrastructure</h3></div><span>{pending ? "Loading" : malwareConnected ? "Current" : "Not enabled"}</span></div>
          {malwareConnected ? <>
            <p className="signal-time">Retrieved <SourceTime value={threatfox?.retrieved_at ?? undefined} /> - {threatfox?.items.length ?? 0} recent indicators</p>
            <ol className="signal-stream">{(threatfox?.items ?? []).slice(0, 10).map((item, index) => <li key={`${item.indicator}-${index}`}><span className="signal-dot signal-malware" aria-hidden="true" /><div><strong>{item.indicator}</strong><small>{item.malware_family || words(item.threat_type || item.category)} - {item.indicator_type}{item.confidence_score != null ? ` - ${item.confidence_score}% confidence` : ""}</small></div><span>{words(item.threat_type || item.category)}{item.last_seen ? <> - Last seen <SourceTime value={item.last_seen} /></> : null}</span></li>)}</ol>
          </> : <p>No validated ThreatFox snapshot is published.</p>}
          <details><summary>Source, entitlement, and meaning</summary><p>{threatfox?.attribution ?? "abuse.ch ThreatFox"}. Enabled for personal evaluation only.</p><p>{threatfox?.does_not_mean ?? "An IOC is not proof of customer impact."}</p><p>Before commercial sale or customer use, obtain the required paid entitlement or written authorization.</p></details>
        </section>
        <section className="observation-density" aria-labelledby="density-title">
          <div className="operations-heading"><div><p className="kicker">Independent public layer</p><h3 id="density-title">Reported signal density</h3></div><span>{scanCountry === "all" ? "All reported countries" : `${scanCountry} selected`}</span></div>
          {connected && (data?.countries ?? []).length ? <Choropleth items={data?.countries ?? []} mode="activity" selected={scanCountry} onSelect={setScanCountry} legendText="Count of selected source-reported IP observations by country. This is not attack volume." metricText="Source-reported public IP observations by country" /> : <p>No country-labelled scanning snapshot is published.</p>}
        </section>
        <section aria-labelledby="category-title">
          <h3 id="category-title">Signal types</h3>
          {connected ? <ol className="rank-bars">{(data?.categories ?? []).slice(0, 8).map((item) => <li key={item.category}><span>{words(item.category)}</span><strong>{item.count}</strong></li>)}</ol> : <p>No validated snapshot is published.</p>}
        </section>
        <section aria-labelledby="ports-title">
          <h3 id="ports-title">Observed target ports</h3>
          {connected ? <div className="port-cloud">{(data?.ports ?? []).slice(0, 12).map((item) => <span key={item.port}><strong>{item.port}</strong>{item.service ? ` ${item.service}` : ""}</span>)}</div> : <p>Port activity appears only after a validated source snapshot.</p>}
        </section>
        <section aria-labelledby="meaning-title">
          <h3 id="meaning-title">What requires action</h3>
          
          <a className="btn primary" href="/services">Review enterprise relevance</a>
        </section>
      </div>
      </details>
    </section>
  );
}
