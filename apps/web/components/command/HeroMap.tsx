"use client";

import { useEffect, useMemo, useState } from "react";

import { SourceTime } from "@/components/command/SourceTime";
import { Choropleth } from "@/components/landscape/Choropleth";
import { api } from "@/lib/api";
import { humanize } from "@/lib/humanize";
import { TRUTH, type TruthKey } from "@/lib/vocabulary";
import { MAP_MODES, type MapMode } from "@/lib/map-modes";
import { presentTelemetry, telemetryHeadline } from "@/lib/telemetry-state";

type Country = { code: string; name: string };
type GeoItem = { country: string; name?: string; count: number; maturities?: Record<string, number> };
type Geo = { meaning?: string; items: GeoItem[] };
type Point = { country: string | null; name: string | null; target?: string | null; target_name?: string | null; value: number | null };
type WindowView = {
  items: Point[];
  targets: Point[];
  paths: Point[];
  normalization?: string | null;
  units?: string | null;
  source_updated_at?: string | null;
};
type Activity = {
  state: string;
  primary: { label: string; limitations: string[]; normalization?: string | null; units?: string | null; source_updated_at?: string | null; comparison: string };
  items: Point[];
  targets: Point[];
  paths: Point[];
  windows?: Record<string, WindowView>;
};

type RouteScope = "all" | "cross-border" | "domestic";

function formatValue(value: number): string {
  return value.toLocaleString(undefined, { maximumFractionDigits: 3 });
}

function rankCountries(flows: { origin: string; originName: string; target: string; targetName: string; value: number }[], role: "origin" | "target") {
  const totals = new Map<string, { code: string; name: string; value: number }>();
  for (const flow of flows) {
    const code = role === "origin" ? flow.origin : flow.target;
    const name = role === "origin" ? flow.originName : flow.targetName;
    const row = totals.get(code) ?? { code, name, value: 0 };
    row.value += flow.value;
    totals.set(code, row);
  }
  return [...totals.values()].sort((left, right) => right.value - left.value);
}

const MODES = ["activity", "advisory", "exposure"] as const;

function readCountry(fallback = "all"): string {
  if (typeof window === "undefined") return fallback;
  return new URLSearchParams(window.location.search).get("country") || fallback;
}

function maturityText(maturities: Record<string, number> | undefined): string {
  const entries = Object.entries(maturities ?? {}).filter(([, count]) => count > 0);
  if (!entries.length) return "Recorded";
  return entries.map(([key, count]) => `${TRUTH[key as TruthKey]?.label ?? key} ${count}`).join(", ");
}

export function HeroMap({ preview = false }: { preview?: boolean }) {
  const [mode, setMode] = useState<MapMode>("activity");
  const [role, setRole] = useState<"path" | "origin" | "target">("path");
  const [routeScope, setRouteScope] = useState<RouteScope>(preview ? "cross-border" : "all");
  const [windowName, setWindowName] = useState("24h");
  const [geo, setGeo] = useState<Geo | null>(null);
  const [activity, setActivity] = useState<Activity | null>(null);
  const [pending, setPending] = useState(true);
  const [countries, setCountries] = useState<Country[]>([]);
  const [query, setQuery] = useState("");
  const [country, setCountry] = useState("all");
  useEffect(() => {
    setCountry(readCountry("all"));
    const onPop = () => setCountry(readCountry());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [preview]);
  useEffect(() => {
    const controller = new AbortController();
    api<{ countries: Country[] }>("/api/v1/landscape/countries", { signal: controller.signal })
      .then((page) => setCountries(page.countries))
      .catch(() => setCountries([]));
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    api<Activity>("/api/v1/telemetry/activity", { signal: controller.signal })
      .then(setActivity)
      .catch(() => setActivity(null))
      .finally(() => { window.clearTimeout(timeout); setPending(false); });
    return () => { window.clearTimeout(timeout); controller.abort(); };
  }, []);
  useEffect(() => {
    if (mode !== "advisory") return;
    const controller = new AbortController();
    api<Geo>("/api/v1/landscape/geography?metric=authority_jurisdiction", { signal: controller.signal }).then(setGeo).catch(() => setGeo(null));
    return () => controller.abort();
  }, [mode]);

  function selectCountry(code: string) {
    setCountry(code);
    const url = new URL(window.location.href);
    if (code === "all") url.searchParams.delete("country");
    else url.searchParams.set("country", code);
    window.history.pushState(null, "", url);
  }

  const catalog = useMemo(
    () => countries.filter((item) => `${item.name} ${item.code}`.toLowerCase().includes(query.toLowerCase())),
    [countries, query],
  );
  const selected = countries.find((item) => item.code === country);
  const config = MAP_MODES[mode];
  const pathMode = mode === "activity" && role === "path";
  const view = activity?.windows?.[windowName];
  const paths = view?.paths ?? activity?.paths ?? [];
  const scopedPaths = paths.filter((item) => (routeScope === "all" || (routeScope === "domestic" ? item.country === item.target : item.country !== item.target))
    && (country === "all" || item.country === country || item.target === country));
  const measured = role === "path" ? scopedPaths : role === "target" ? view?.targets ?? activity?.targets ?? [] : view?.items ?? activity?.items ?? [];
  const state = presentTelemetry(pending ? null : activity ? { state: activity.state, hasSnapshot: Boolean(view?.source_updated_at || activity.primary.source_updated_at) } : { state: "failed_no_snapshot" }, pending);
  const showMeasurements = state === "current" || state === "stale" || state === "failed_with_last_known_good";
  const advisoryItems = geo?.items ?? [];
  const allFlows = pathMode && showMeasurements ? paths.flatMap((item) => (
    item.country && item.name && item.target && item.target_name && item.value !== null
      ? [{ origin: item.country, originName: item.name, target: item.target, targetName: item.target_name, value: item.value }]
      : []
  )) : [];
  const flows = allFlows.filter((flow) => (routeScope === "all" || (routeScope === "domestic" ? flow.origin === flow.target : flow.origin !== flow.target))
    && (country === "all" || flow.origin === country || flow.target === country));
  const flowCountries = new Map<string, number>();
  for (const flow of flows) {
    flowCountries.set(flow.origin, (flowCountries.get(flow.origin) ?? 0) + flow.value);
    flowCountries.set(flow.target, (flowCountries.get(flow.target) ?? 0) + flow.value);
  }
  const mapItems = mode === "advisory"
    ? advisoryItems.map((item) => ({ country: item.country, count: item.count }))
    : mode === "activity" && showMeasurements
      ? (pathMode ? [...flowCountries].map(([country, count]) => ({ country, count })) : measured.flatMap((item) => item.country && item.value !== null ? [{ country: item.country, count: item.value }] : []))
      : [];
  const visibleRows = mode === "advisory" ? advisoryItems : mode === "activity" ? measured : [];
  const leadingPath = flows[0];
  const originRanks = rankCountries(flows, "origin");
  const targetRanks = rankCountries(flows, "target");
  const uniqueCountries = new Set(flows.flatMap((flow) => [flow.origin, flow.target])).size;
  const maxRouteValue = Math.max(1, ...flows.map((flow) => flow.value));
  const updated = view?.source_updated_at ?? activity?.primary.source_updated_at;
  const normalization = view?.normalization ?? activity?.primary.normalization;
  const units = view?.units ?? activity?.primary.units;

  return (
    <section className={"map-frame threat-pulse" + (preview ? " is-preview" : "")} aria-label={preview ? "Global threat pulse" : config.title}>
      <h2>{preview ? "Global threat pulse" : config.title}</h2>
      {preview ? null : (
        <div className="metric-switch" role="group" aria-label="Map mode">
          {MODES.map((value) => (
            <button key={value} className="btn secondary" type="button" aria-pressed={mode === value} onClick={() => setMode(value)}>{MAP_MODES[value].title}</button>
          ))}
        </div>
      )}
      {state === "loading" && mode === "activity" ? <p className="skeleton" aria-busy="true">Loading global activity…</p> : null}
      {mode === "activity" && state !== "loading" ? (
        <>
          <p className="pulse-intro">{preview ? "Latest Cloudflare-observed origin-to-target paths. Aggregated global observations, not customer traffic." : config.interpretation}</p>
          {showMeasurements ? (
            <>
              <p className="pulse-meta">
                {role === "path" ? "Observed paths" : role === "origin" ? "Origins" : "Targets"} · {windowName}
                {normalization ? ` · ${humanize(normalization)}` : ""}
                {units ? ` · ${units}` : ""}
                {updated ? <> · <SourceTime value={updated} /></> : null}
                {state === "stale" ? " · Stale" : ""}
              </p>
              {role === "path" && allFlows.length ? (
                <div className="pulse-stats">
                  <div><strong>{flows.length}</strong><span>Observed routes shown</span></div>
                  <div><strong>{uniqueCountries}</strong><span>Countries represented</span></div>
                  <div><strong>{leadingPath ? `${leadingPath.originName} → ${leadingPath.targetName}` : "No matching route"}</strong><span>Leading observed path</span></div>
                  <div><strong>{updated ? <SourceTime value={updated} /> : "—"}</strong><span>Source update</span></div>
                </div>
              ) : null}
            </>
          ) : <p>{telemetryHeadline(state)}</p>}
          {role === "path" ? (
            <div className="route-scope" role="group" aria-label="Route scope">
              <span>Show routes</span>
              {(["all", "cross-border", "domestic"] as RouteScope[]).map((scope) => (
                <button key={scope} className="route-scope-button" type="button" aria-pressed={routeScope === scope} onClick={() => setRouteScope(scope)}>
                  {scope === "all" ? "All" : scope === "cross-border" ? "Cross-border" : "Domestic"}
                </button>
              ))}
            </div>
          ) : null}
          {preview ? null : (
            <div className="metric-switch" role="group" aria-label="Activity measurement">
              <button className="btn secondary" type="button" aria-pressed={role === "path"} onClick={() => setRole("path")}>Paths</button>
              <button className="btn secondary" type="button" aria-pressed={role === "origin"} onClick={() => setRole("origin")}>Origins</button>
              <button className="btn secondary" type="button" aria-pressed={role === "target"} onClick={() => setRole("target")}>Targets</button>
              <button className="btn secondary" type="button" aria-pressed={windowName === "24h"} onClick={() => setWindowName("24h")}>24 hours</button>
              <button className="btn secondary" type="button" aria-pressed={windowName === "7d"} onClick={() => setWindowName("7d")}>7 days</button>
            </div>
          )}
          {preview ? null : (
            <details>
              <summary>How to interpret this</summary>
              <p>{preview ? "" : config.interpretation}</p>
              <p>{config.metric}. {role === "path" ? "Paths aggregate origin and target country pairs." : role === "origin" ? "Origin is the client IP location." : "Target is the zone billing location when supplied."} {activity?.primary.comparison}</p>
              <p>{(activity?.primary.limitations ?? []).join(" ")}</p>
            </details>
          )}
        </>
      ) : null}
      {mode === "advisory" ? (
        <>
          <details>
            <summary>How to interpret this</summary>
            <p>{config.interpretation}</p>
            <p>{geo?.meaning} Synthetic reference records stay labelled. A jurisdiction is not an attacker origin.</p>
          </details>
        </>
      ) : null}
      {mode === "exposure" ? (
        <>
          <details>
            <summary>How to interpret this</summary>
            <p>{config.interpretation}</p>
            <p>Norway, Sweden, and Finland are in the synthetic profile. Advisory geography and Cloudflare measurements are not evidence that a customer system was reached.</p>
          </details>
        </>
      ) : null}
      {preview ? null : (
        <label className="form cc-search">Search countries
          <input aria-label="Search countries" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search by name" />
        </label>
      )}
      {preview ? (
        <label className="compact-country">Country
          <select aria-label="Country" disabled={countries.length === 0} value={countries.length === 0 ? "loading" : country} onChange={(event) => selectCountry(event.target.value)}>
            {countries.length === 0 ? <option value="loading">Loading countries</option> : <>
              <option value="all">All countries</option>
              {countries.map((item) => <option key={item.code} value={item.code}>{item.name}</option>)}
            </>}
          </select>
        </label>
      ) : null}
      {preview ? null : (
        <>
      <label className="form">Country
        <select aria-label="Country" disabled={countries.length === 0} value={countries.length === 0 ? "loading" : country} onChange={(event) => selectCountry(event.target.value)}>
          {countries.length === 0 ? <option value="loading">Loading countries</option> : (
            <>
              <option value="all">All countries</option>
              {catalog.map((item) => <option key={item.code} value={item.code}>{item.name}</option>)}
            </>
          )}
        </select>
      </label>
      <p className="sr-only" role="status">{countries.length === 0 ? "Loading countries." : selected ? `${selected.name} is selected.` : country !== "all" ? `${country} is selected.` : "All countries are selected."}</p>
        </>
      )}
      <Choropleth items={mapItems} flows={flows} mode={mode} selected={country} onSelect={selectCountry} />
      {mode === "activity" && pathMode && showMeasurements && !preview ? (
        <div className="operations-board">
          <section className="route-feed" aria-labelledby="route-feed-title">
            <div className="operations-heading"><h3 id="route-feed-title">Observed route ranking</h3><span>{routeScope === "all" ? "All routes" : routeScope === "domestic" ? "Domestic only" : "Cross-border only"}</span></div>
            {flows.length ? (
              <ol>
                {flows.slice(0, preview ? 5 : 10).map((flow, index) => (
                  <li key={`${flow.origin}-${flow.target}-${index}`}>
                    <span className="route-rank">{String(index + 1).padStart(2, "0")}</span>
                    <span><strong>{flow.originName}</strong><small>{flow.origin}</small></span>
                    <span className="route-arrow" aria-hidden="true">→</span>
                    <span><strong>{flow.targetName}</strong><small>{flow.target}</small></span>
                    <span className="route-value"><strong>{formatValue(flow.value)}</strong><i style={{ width: `${Math.max(4, (flow.value / maxRouteValue) * 100)}%` }} /></span>
                  </li>
                ))}
              </ol>
            ) : <p>No routes match this view.</p>}
          </section>
          <div className="hotspot-columns">
            <section aria-labelledby="origin-hotspots"><h3 id="origin-hotspots">Top origins</h3><ol>{originRanks.slice(0, 5).map((item) => <li key={item.code}><span>{item.name}</span><strong>{formatValue(item.value)}</strong></li>)}</ol></section>
            <section aria-labelledby="target-hotspots"><h3 id="target-hotspots">Top targets</h3><ol>{targetRanks.slice(0, 5).map((item) => <li key={item.code}><span>{item.name}</span><strong>{formatValue(item.value)}</strong></li>)}</ol></section>
          </div>
        </div>
      ) : null}
      {preview ? <p><a href="/threats">Open global observations</a></p> : null}
      {preview ? null : <div className="table-scroll" tabIndex={0}>
        <table>
          <caption>{pathMode ? "Top observed origin-to-target paths." : "Country measurements. Missing data stays blank rather than zero."}</caption>
          <thead><tr><th scope="col">{pathMode ? "Path" : "Country"}</th><th scope="col">Value</th><th scope="col">State</th></tr></thead>
          <tbody>
            {mode === "exposure" ? (
              <tr><th scope="row">Geographic exposure</th><td>—</td><td>No verdict</td></tr>
            ) : mode === "advisory" ? visibleRows.map((item) => {
              const row = item as GeoItem;
              return (
                <tr key={row.country} aria-selected={row.country === country} className={row.country === country ? "is-selected" : undefined} onClick={() => selectCountry(row.country)}>
                  <th scope="row">{row.name ?? row.country}</th>
                  <td>{row.count}</td>
                  <td>{maturityText(row.maturities)}</td>
                </tr>
              );
            }) : showMeasurements ? (visibleRows as Point[]).map((item) => (
              <tr key={`${item.country}-${item.target ?? ""}-${item.value}`} aria-selected={item.country === country} className={item.country === country ? "is-selected" : undefined} onClick={() => item.country && selectCountry(item.country)}>
                <th scope="row">{pathMode ? `${item.name ?? item.country} → ${item.target_name ?? item.target}` : item.name ?? item.country}</th>
                <td>{item.value === null ? "—" : item.value}</td>
                <td>{item.value === null ? "No data returned" : pathMode ? "Aggregated path" : item.value === 0 ? "Zero" : "Returned"}</td>
              </tr>
            )) : (
              <tr><th scope="row">Measurement</th><td>—</td><td>{state === "disabled" ? "Not enabled" : state === "failed_without_snapshot" ? "No snapshot" : "Refresh failed"}</td></tr>
            )}
          </tbody>
        </table>
      </div>}
    </section>
  );
}
