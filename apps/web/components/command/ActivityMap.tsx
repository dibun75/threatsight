"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";

type Location = { code: string; name: string; role: string; layer: string; magnitude: number; lon: number; lat: number };
type Activity = {
  label: string;
  source: string;
  measurement: string;
  unit: string;
  window: string;
  freshness: string;
  maturity: string;
  live: boolean;
  limitations: string[];
  locations: Location[];
  arcs: { origin: string; target: string; magnitude: number; meaning: string }[];
};

const WINDOWS = ["1h", "24h", "7d", "30d"] as const;

function project(lon: number, lat: number) {
  return { x: ((lon + 180) / 360) * 800, y: ((90 - lat) / 180) * 400 };
}

export function ActivityMap() {
  const [windowName, setWindow] = useState<(typeof WINDOWS)[number]>("24h");
  const [direction, setDirection] = useState("target");
  const [body, setBody] = useState<Activity | null>(null);
  const [outlines, setOutlines] = useState<string[]>([]);
  useEffect(() => {
    const controller = new AbortController();
    api<Activity>(`/api/v1/activity/summary?window=${windowName}&direction=${direction}&layer=all`, { signal: controller.signal })
      .then(setBody)
      .catch(() => setBody(null));
    return () => controller.abort();
  }, [windowName, direction]);
  useEffect(() => {
    fetch("/geo/ne_110m_admin_0_countries.geojson").then((response) => response.json()).then((document) => {
      const paths: string[] = [];
      for (const feature of (document.features ?? []).slice(0, 180)) {
        const geometry = feature.geometry;
        const polygons = geometry?.type === "Polygon" ? [geometry.coordinates] : geometry?.coordinates;
        if (!Array.isArray(polygons)) continue;
        const drawn = polygons.map((polygon: number[][][]) => {
          const ring = Array.isArray(polygon?.[0]) ? polygon[0] : [];
          return ring.map((point: number[], index: number) => {
            const spot = project(point[0], point[1]);
            return `${index === 0 ? "M" : "L"}${spot.x} ${spot.y}`;
          }).join(" ") + "Z";
        }).join(" ");
        if (drawn.startsWith("M")) paths.push(drawn);
      }
      setOutlines(paths);
    }).catch(() => setOutlines([]));
  }, []);
  const max = Math.max(1, ...(body?.locations.map((item) => item.magnitude) ?? [1]));
  return (
    <section aria-label="Observed telemetry">
      <h2>Observed attack telemetry unavailable</h2>
      <p>Customer firewall, WAF, IDS, SIEM, or a commercially licensed telemetry source is required. No approved live source is connected.</p>
      <p>Connector freshness: no live connector has reported. Source health is on this page.</p>
      <details className="disclosure">
        <summary>Reference telemetry simulation</summary>
        <p className="state-badge synthetic">Synthetic demonstration — not live attack telemetry.</p>
        <div className="metric-switch" role="group" aria-label="Simulation window">
          {WINDOWS.map((item) => <button key={item} className="btn secondary" type="button" aria-pressed={windowName === item} onClick={() => setWindow(item)}>{item}</button>)}
        </div>
        <div className="metric-switch" role="group" aria-label="Simulation direction">
          {["target", "origin", "pair"].map((item) => <button key={item} className="btn secondary" type="button" aria-pressed={direction === item} onClick={() => setDirection(item)}>{item}</button>)}
        </div>
        <p>Measurement: {body?.measurement ?? "…"}. Unit: {body?.unit ?? "…"}. Window: {body?.window ?? windowName}. Direction: {direction}. Source: {body?.source ?? "…"}. Freshness: {body?.freshness ?? "…"}. Maturity: {body?.maturity ?? "…"}.</p>
        <div className="legend" aria-label="Marker size legend"><span>Smaller marker</span><span className="swatch low" /><span className="swatch high" /><span>Larger marker, higher synthetic count</span></div>
        <svg viewBox="0 0 800 400" role="img" aria-label="Reference telemetry simulation on a geographic basemap. The table states the same counts.">
          {outlines.map((path, index) => <path key={index} d={path} fill="#122b34" stroke="#4e8fa8" strokeWidth="0.3" />)}
          {(body?.locations ?? []).map((item) => {
            const spot = project(item.lon, item.lat);
            return <circle key={`${item.code}-${item.role}`} cx={spot.x} cy={spot.y} r={4 + (item.magnitude / max) * 14} fill="#d4a24c"><title>{item.name}: {item.magnitude}</title></circle>;
          })}
        </svg>
        <p className="map-tooltip" role="status">{body?.label ?? "Synthetic demonstration — not live attack telemetry."}</p>
        <div className="table-scroll" tabIndex={0}>
          <table>
            <caption>Synthetic demonstration counts. These are not live attack telemetry.</caption>
            <thead><tr><th scope="col">Location</th><th scope="col">Role</th><th scope="col">Layer</th><th scope="col">Count</th></tr></thead>
            <tbody>
              {(body?.locations ?? []).map((item) => <tr key={`${item.code}-${item.role}`}><th scope="row">{item.name}</th><td>{item.role}</td><td>{item.layer}</td><td>{item.magnitude}</td></tr>)}
            </tbody>
          </table>
        </div>
        <ul>{(body?.limitations ?? []).map((item) => <li key={item}>{item}</li>)}</ul>
      </details>
    </section>
  );
}
