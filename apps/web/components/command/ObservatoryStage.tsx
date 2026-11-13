"use client";

import { useEffect, useMemo, useState } from "react";

import { SourceTime } from "@/components/command/SourceTime";
import { Choropleth, type MapPoint } from "@/components/landscape/Choropleth";
import { publicCountryName } from "@/lib/country-names";
import { api } from "@/lib/api";
import type { TickerEntry } from "@/lib/observatory-ticker";
import { presentTelemetry } from "@/lib/telemetry-state";

type Point = { country: string | null; name: string | null; target?: string | null; target_name?: string | null; value: number | null };
type WindowView = { paths: Point[]; normalization?: string | null; units?: string | null; source_updated_at?: string | null };
type Activity = {
  state: string;
  primary: { source_updated_at?: string | null; normalization?: string | null; units?: string | null };
  paths: Point[];
  windows?: Record<string, WindowView>;
};
type Flow = { origin: string; originName: string; target: string; targetName: string; value: number };
type Scope = "all" | "cross-border" | "domestic";
type RankRow = { code: string; name: string; value: number };

const SCOPES: { key: Scope; label: string }[] = [
  { key: "all", label: "All" },
  { key: "cross-border", label: "Cross-border" },
  { key: "domestic", label: "Domestic" },
];

/** Map windows in the 800 x 400 equirectangular drawing space. */
export const REGIONS: { key: string; label: string; viewBox: string }[] = [
  { key: "world", label: "Worldwide", viewBox: "0 0 800 400" },
  { key: "north-america", label: "North America", viewBox: "20 30 270 160" },
  { key: "south-america", label: "South America", viewBox: "150 160 220 175" },
  { key: "europe", label: "Europe", viewBox: "335 35 175 95" },
  { key: "middle-east", label: "Middle East", viewBox: "440 95 120 90" },
  { key: "africa", label: "Africa", viewBox: "340 110 200 180" },
  { key: "asia", label: "Asia", viewBox: "490 60 250 145" },
  { key: "oceania", label: "Oceania", viewBox: "620 170 180 150" },
];

const FEED_ROWS = 5;

function share(value: number): string {
  return `${value.toLocaleString("en", { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`;
}

function rank(flows: Flow[], role: "origin" | "target"): RankRow[] {
  const totals = new Map<string, RankRow>();
  for (const flow of flows) {
    const code = role === "origin" ? flow.origin : flow.target;
    const row = totals.get(code) ?? { code, name: role === "origin" ? flow.originName : flow.targetName, value: 0 };
    row.value += flow.value;
    totals.set(code, row);
  }
  return [...totals.values()].sort((a, b) => b.value - a.value).slice(0, 6);
}

function RankList({ title, note, rows, tone, format, onPick }: { title: string; note: string; rows: RankRow[]; tone: string; format: (value: number) => string; onPick?: (code: string) => void }) {
  const top = Math.max(1, ...rows.map((row) => row.value));
  return (
    <section className={`obs-rank ${tone}`} aria-label={title}>
      <h3>{title}<small>{note}</small></h3>
      {rows.length ? (
        <ol>
          {rows.map((row) => (
            <li key={row.code}>
              <button type="button" onClick={onPick ? () => onPick(row.code) : undefined} disabled={!onPick}>
                <span>{row.name}</span>
                <strong>{format(row.value)}</strong>
                <i style={{ width: `${Math.max(4, (row.value / top) * 100)}%` }} />
              </button>
            </li>
          ))}
        </ol>
      ) : <p>No data</p>}
    </section>
  );
}

/** Keeps its own timer so a new row never re-renders the map. */
function IndicatorFeed({ feed }: { feed: TickerEntry[] }) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (feed.length <= FEED_ROWS) return undefined;
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return undefined;
    const timer = window.setInterval(() => setTick((current) => current + 1), 4000);
    return () => window.clearInterval(timer);
  }, [feed.length]);
  if (!feed.length) return null;
  const rows = feed.length <= FEED_ROWS ? feed : Array.from({ length: FEED_ROWS }, (_, index) => feed[(tick + index) % feed.length]);
  return (
    <section className="obs-feed" aria-label="Reported indicators from public feeds. Not customer traffic.">
      <h3>Reported indicators<small>public feeds</small></h3>
      <ol aria-live="off">
        {rows.map((entry) => (
          <li key={entry.key}>
            <b className={`feed-source is-${entry.source.toLowerCase()}`}>{entry.source}</b>
            <span>{entry.label}</span>
            <small>{entry.detail}</small>
          </li>
        ))}
      </ol>
    </section>
  );
}

export type StageSignals = { scan: { country: string; count: number }[]; c2: { country: string; count: number }[] };
export type StageThreat = { name: string; count: number };

export function ObservatoryStage({ extra, signals, feed = [], threats = [] }: { extra?: React.ReactNode; signals?: StageSignals; feed?: TickerEntry[]; threats?: StageThreat[] }) {
  const [layers, setLayers] = useState({ routes: true, scan: true, c2: true });
  const [activity, setActivity] = useState<Activity | null>(null);
  const [pending, setPending] = useState(true);
  const [windowName, setWindowName] = useState("24h");
  const [scope, setScope] = useState<Scope>("cross-border");
  const [country, setCountry] = useState("all");
  const [region, setRegion] = useState("world");
  useEffect(() => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    api<Activity>("/api/v1/telemetry/activity", { signal: controller.signal })
      .then(setActivity)
      .catch(() => setActivity(null))
      .finally(() => { window.clearTimeout(timeout); setPending(false); });
    return () => { window.clearTimeout(timeout); controller.abort(); };
  }, []);
  const view = activity?.windows?.[windowName];
  const updated = view?.source_updated_at ?? activity?.primary.source_updated_at;
  const state = presentTelemetry(pending ? null : activity ? { state: activity.state, hasSnapshot: Boolean(updated) } : { state: "failed_no_snapshot" }, pending);
  const live = state === "current" || state === "stale" || state === "failed_with_last_known_good";
  const all = useMemo<Flow[]>(() => (view?.paths ?? activity?.paths ?? []).flatMap((item) => (
    item.country && item.name && item.target && item.target_name && item.value !== null
      ? [{ origin: item.country, originName: item.name, target: item.target, targetName: item.target_name, value: item.value }]
      : []
  )), [view, activity]);
  const flows = all.filter((flow) => (scope === "all" || (scope === "domestic" ? flow.origin === flow.target : flow.origin !== flow.target))
    && (country === "all" || flow.origin === country || flow.target === country));
  const origins = rank(flows, "origin");
  const targets = rank(flows, "target");
  const mapItems = useMemo(() => {
    const totals = new Map<string, number>();
    for (const flow of flows) {
      totals.set(flow.origin, (totals.get(flow.origin) ?? 0) + flow.value);
      totals.set(flow.target, (totals.get(flow.target) ?? 0) + flow.value);
    }
    return live ? [...totals].map(([code, count]) => ({ country: code, count })) : [];
  }, [flows, live]); // eslint-disable-line react-hooks/exhaustive-deps
  const scan = signals?.scan;
  const c2 = signals?.c2;
  const points = useMemo<MapPoint[]>(() => [
    ...(layers.scan ? (scan ?? []).map((item) => ({ country: item.country, layer: "scan" as const, count: item.count, label: `${publicCountryName(item.country, item.country)}: ${item.count} DShield-reported IPs` })) : []),
    ...(layers.c2 ? (c2 ?? []).map((item) => ({ country: item.country, layer: "c2" as const, count: item.count, label: `${publicCountryName(item.country, item.country)}: ${item.count} Feodo botnet C2 ${item.count === 1 ? "server" : "servers"}` })) : []),
  ], [scan, c2, layers.scan, layers.c2]);
  const toggle = (key: keyof typeof layers) => setLayers((current) => ({ ...current, [key]: !current[key] }));
  const scanCount = (signals?.scan ?? []).length;
  const c2Count = (signals?.c2 ?? []).reduce((total, item) => total + item.count, 0);
  const badge = pending ? "Loading" : state === "current" ? "Live" : state === "stale" ? "Stale" : live ? "Last known" : "Not enabled";
  const viewBox = REGIONS.find((item) => item.key === region)?.viewBox ?? REGIONS[0].viewBox;
  const threatRows = threats.slice(0, 6).map((item) => ({ code: item.name, name: item.name, value: item.count }));

  return (
    <section className="obs-stage" aria-labelledby="observatory-title">
      <div className="obs-map">
        <Choropleth stage viewBox={viewBox} items={layers.routes ? mapItems : []} points={points} flows={live && layers.routes ? flows : []} mode="activity" selected={country} onSelect={(code) => setCountry((current) => (current === code ? "all" : code))} metricText="Cloudflare Radar observed origin-to-target attack paths" />
        {!live && !pending ? <p className="obs-offline">No Cloudflare Radar snapshot is published. No routes are drawn.</p> : null}
        <header className="obs-top">
          <div className="obs-title">
            <h2 id="observatory-title">Threat Observatory</h2>
            <span className={`obs-badge is-${badge.toLowerCase().replace(" ", "-")}`}><i aria-hidden="true" />{badge}</span>
          </div>
          <div className="obs-controls">
            <div role="group" aria-label="Window">
              {["24h", "7d"].map((name) => <button key={name} type="button" aria-pressed={windowName === name} onClick={() => setWindowName(name)}>{name}</button>)}
            </div>
            <div role="group" aria-label="Route scope">
              {SCOPES.map((item) => <button key={item.key} type="button" aria-pressed={scope === item.key} onClick={() => setScope(item.key)}>{item.label}</button>)}
            </div>
            {country !== "all" ? <button type="button" className="obs-clear" onClick={() => setCountry("all")}>Clear {publicCountryName(country, country)} ✕</button> : null}
          </div>
          <dl className="obs-kpis">
            <div><dt>Routes</dt><dd>{live ? flows.length : "—"}</dd></div>
            <div><dt>Origins</dt><dd>{live ? origins.length : "—"}</dd></div>
            <div><dt>Targets</dt><dd>{live ? targets.length : "—"}</dd></div>
            <div><dt>Scan countries</dt><dd>{scanCount || "—"}</dd></div>
            <div><dt>Botnet C2s</dt><dd>{c2Count || "—"}</dd></div>
          </dl>
        </header>
        <nav className="obs-region" aria-label="Region">
          <h3>Region</h3>
          {REGIONS.map((item) => <button key={item.key} type="button" aria-pressed={region === item.key} onClick={() => setRegion(item.key)}>{item.label}</button>)}
        </nav>
        <div className="obs-side">
          <RankList title="Top origins" note="share of routes" rows={origins} tone="is-origin" format={share} onPick={setCountry} />
          <RankList title="Top targets" note="share of routes" rows={targets} tone="is-target" format={share} onPick={setCountry} />
          <RankList title="Top malware" note="reported indicators" rows={threatRows} tone="is-threat" format={(value) => value.toLocaleString("en")} />
        </div>
        <IndicatorFeed feed={feed} />
        <aside className="obs-legend" aria-label="Map layers">
          <h3>Legend</h3>
          <button type="button" aria-pressed={layers.routes} onClick={() => toggle("routes")}><i className="k-cross" />Attack routes</button>
          <span className="obs-legend-sub"><i className="k-origin" />Origin <i className="k-target" />Target</span>
          <button type="button" aria-pressed={layers.scan} onClick={() => toggle("scan")} disabled={!scanCount}><i className="k-scan" />Reported IPs</button>
          <button type="button" aria-pressed={layers.c2} onClick={() => toggle("c2")} disabled={!c2Count}><i className="k-c2" />Botnet C2</button>
        </aside>
        <footer className="obs-source">
          Cloudflare Radar · DShield · abuse.ch · aggregate, not individual attacks, not customer traffic{updated ? <> · updated <SourceTime value={updated} /></> : null}
        </footer>
      </div>
      {extra}
    </section>
  );
}
