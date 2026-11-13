"use client";

import { useEffect, useMemo, useState } from "react";

import { POINT_MARKERS, canonicalIso, reconcileMeasurement } from "@/lib/country-geometry";
import { publicCountryName } from "@/lib/country-names";
import type { MapMode } from "@/lib/map-modes";
import { MAP_MODES } from "@/lib/map-modes";

type Feature = { properties: { iso_a2: string; name: string }; geometry: { type: string; coordinates: number[][][] | number[][][][] } };
type Item = { country: string; count: number };
export type MapPoint = { country: string; layer: "scan" | "c2"; count: number; label: string };
type Flow = { origin: string; originName: string; target: string; targetName: string; value: number };

function project(lon: number, lat: number): [number, number] {
  return [(lon + 180) * (800 / 360), (90 - lat) * (400 / 180)];
}

function ring(points: number[][]): string {
  return points.map((point, index) => `${index === 0 ? "M" : "L"}${project(point[0], point[1]).join(" ")}`).join(" ") + "Z";
}

function geometryPath(geometry: Feature["geometry"]): string {
  if (geometry.type === "Polygon") return (geometry.coordinates as number[][][]).map(ring).join(" ");
  if (geometry.type === "MultiPolygon") return (geometry.coordinates as number[][][][]).map((polygon) => polygon.map(ring).join(" ")).join(" ");
  return "";
}

function geometryCenter(geometry: Feature["geometry"]): [number, number] {
  const points = geometry.type === "Polygon"
    ? (geometry.coordinates as number[][][]).flat()
    : (geometry.coordinates as number[][][][]).flat(2);
  const radians = points.map((point) => point[0] * (Math.PI / 180));
  const longitude = Math.atan2(
    radians.reduce((sum, value) => sum + Math.sin(value), 0),
    radians.reduce((sum, value) => sum + Math.cos(value), 0),
  ) * (180 / Math.PI);
  const latitudes = points.map((point) => point[1]);
  return project(
    longitude,
    (Math.min(...latitudes) + Math.max(...latitudes)) / 2,
  );
}

/** Share of the full 800-unit map that a viewBox shows: 1 for the world, smaller when zoomed in. */
export function mapZoom(viewBox: string): number {
  const width = Number(viewBox.trim().split(/\s+/)[2]);
  return Number.isFinite(width) && width > 0 ? Math.min(1, width / 800) : 1;
}

function flowPath(from: [number, number], to: [number, number]): string {
  const distance = Math.hypot(to[0] - from[0], to[1] - from[1]);
  if (distance < 1) {
    const [x, y] = from;
    return `M ${x - 8} ${y} C ${x - 24} ${y - 28}, ${x + 24} ${y - 28}, ${x + 8} ${y} C ${x + 20} ${y + 14}, ${x - 20} ${y + 14}, ${x - 8} ${y}`;
  }
  const controlX = (from[0] + to[0]) / 2;
  const controlY = (from[1] + to[1]) / 2 - Math.min(90, Math.max(18, distance * 0.22));
  return `M ${from[0]} ${from[1]} Q ${controlX} ${controlY} ${to[0]} ${to[1]}`;
}

export function Choropleth({
  items,
  flows = [],
  mode,
  selected,
  onSelect,
  legendText,
  metricText,
  stage = false,
  points = [],
  viewBox = "0 0 800 400",
}: {
  items: Item[];
  flows?: Flow[];
  mode: MapMode;
  selected: string;
  onSelect: (code: string) => void;
  legendText?: string;
  metricText?: string;
  stage?: boolean;
  points?: MapPoint[];
  viewBox?: string;
}) {
  const [features, setFeatures] = useState<Feature[]>([]);
  const [ready, setReady] = useState(false);
  const [hover, setHover] = useState("");
  const config = MAP_MODES[mode];
  const shownLegend = legendText ?? config.legend;
  const shownMetric = metricText ?? config.metric;
  useEffect(() => {
    let active = true;
    fetch("/geo/ne_110m_admin_0_countries.geojson")
      .then((response) => response.json())
      .then((document) => { if (active) setFeatures(document.features ?? []); })
      .catch(() => { if (active) setFeatures([]); })
      .finally(() => { if (active) setReady(true); });
    return () => { active = false; };
  }, []);
  const drawn = useMemo(() => features.flatMap((feature) => {
    const iso = canonicalIso(feature.properties);
    return iso ? [{ iso, name: feature.properties.name, path: geometryPath(feature.geometry), center: geometryCenter(feature.geometry) }] : [];
  }), [features]);
  const polygons = useMemo(() => new Set(drawn.map((feature) => feature.iso)), [drawn]);
  const counts = new Map(items.map((item) => [item.country, item.count]));
  const max = Math.max(1, ...items.map((item) => item.count));
  const markers = items.flatMap((item) => {
    if (reconcileMeasurement(item.country, polygons) !== "marker") return [];
    const marker = POINT_MARKERS[item.country];
    return marker ? [{ ...marker, count: item.count }] : [];
  });
  const unavailable = items.filter((item) => reconcileMeasurement(item.country, polygons) === "unavailable");
  const centers = useMemo(() => {
    const values = new Map(drawn.map((feature) => [feature.iso, feature.center]));
    for (const marker of Object.values(POINT_MARKERS)) values.set(marker.code, project(marker.lon, marker.lat));
    return values;
  }, [drawn]);
  const visibleFlows = useMemo(() => [...flows]
    .filter((flow) => flow.value >= 0 && centers.has(flow.origin) && centers.has(flow.target))
    .sort((left, right) => right.value - left.value)
    .slice(0, stage ? 40 : 25)
    .map((flow) => ({ ...flow, from: centers.get(flow.origin)!, to: centers.get(flow.target)! })), [centers, flows]);
  const visiblePoints = useMemo(() => points.flatMap((point) => {
    const center = centers.get(point.country);
    return center ? [{ ...point, at: center }] : [];
  }), [centers, points]);
  // Marks are sized in map units, so a zoomed window must shrink them to keep their on-screen size.
  const zoom = mapZoom(viewBox);
  const maxPoint = Math.max(1, ...visiblePoints.map((point) => point.count));
  const maxFlow = Math.max(1, ...visibleFlows.map((flow) => flow.value));
  const focusable = [...drawn.map((feature) => feature.iso), ...markers.map((marker) => marker.code)];
  const selectedItem = items.find((item) => item.country === selected);
  const sourceName = drawn.find((feature) => feature.iso === selected)?.name ?? POINT_MARKERS[selected]?.name ?? selected;
  const selectedName = publicCountryName(selected, sourceName);
  const announcement = selected === "all"
    ? "All countries are selected."
    : `${selectedName}${selectedItem ? `: ${selectedItem.count}` : counts.has(selected) ? `: ${counts.get(selected)}` : ""}.`;

  function focusCode(code: string) {
    document.getElementById(`country-${code}`)?.focus();
  }
  function move(code: string, direction: 1 | -1) {
    const index = focusable.indexOf(code);
    const next = focusable[Math.min(focusable.length - 1, Math.max(0, index + direction))];
    if (next) focusCode(next);
  }
  function choose(code: string) {
    onSelect(code);
  }
  function label(code: string, name: string): string {
    const count = counts.get(code);
    return `${name}, ${count === undefined ? "No data returned" : count}`;
  }
  function fill(code: string): string {
    if (mode === "exposure") return "#14303a";
    const count = counts.get(code);
    if (count === undefined) return "#14303a";
    if (count === 0) return "#0d2129";
    return `rgba(60, 199, 173, ${0.3 + (0.7 * count) / max})`;
  }

  return (
    <div className={"map-frame" + (stage ? " is-stage" : "")}>
      {stage ? null : <div className="legend" aria-label={`${config.title} legend`}>
        <span className="swatch none" />
        <span>No data</span>
        <span>0</span>
        <span className="swatch low" />
        <span className="swatch mid" />
        <span className="swatch high" />
        <span>{mode === "exposure" ? "—" : max}</span>
      </div>}
      {visibleFlows.length && !stage ? (
        <div className="flow-legend" aria-label="Attack path legend">
          <span className="flow-key" aria-hidden="true" />
          <span>Top origin-to-target paths · line weight follows share</span>
        </div>
      ) : null}
      {stage ? null : <p className="legend-note" data-map-mode={mode}>{shownLegend}</p>}
      <p className={stage ? "map-tooltip stage-tooltip" : "map-tooltip"} aria-hidden={hover ? undefined : true}>{hover}</p>
      <p className="map-tooltip sr-only" role="status" id="advisory-geography-tooltip">{announcement}</p>
      <svg className="world-svg" viewBox={viewBox} style={{ "--map-zoom": zoom } as React.CSSProperties} role="group" aria-label={`${shownMetric}. Values are repeated in the table.`}>
        {drawn.map((feature) => (
          <path
            id={`country-${feature.iso}`}
            key={feature.iso}
            d={feature.path}
            tabIndex={0}
            role="button"
            aria-pressed={selected === feature.iso}
            aria-label={label(feature.iso, publicCountryName(feature.iso, feature.name))}
            fill={fill(feature.iso)}
            stroke={selected === feature.iso ? "#f3f5f2" : "#2a5b69"}
            strokeWidth={(selected === feature.iso ? 1.6 : 0.4) * zoom}
            onClick={() => choose(feature.iso)}
            onFocus={() => setHover(label(feature.iso, feature.name))}
            onMouseEnter={() => setHover(label(feature.iso, feature.name))}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") { event.preventDefault(); choose(feature.iso); }
              if (event.key === "ArrowRight") { event.preventDefault(); move(feature.iso, 1); }
              if (event.key === "ArrowLeft") { event.preventDefault(); move(feature.iso, -1); }
            }}
          />
        ))}
        {markers.map((marker) => {
          const [x, y] = project(marker.lon, marker.lat);
          return (
            <circle
              id={`country-${marker.code}`}
              key={marker.code}
              cx={x}
              cy={y}
              r={5 * zoom}
              tabIndex={0}
              role="button"
              aria-pressed={selected === marker.code}
              aria-label={`${label(marker.code, marker.name)}. Point marker.`}
              fill={fill(marker.code)}
              stroke={selected === marker.code ? "#f3f5f2" : "#d4a24c"}
              strokeWidth={(selected === marker.code ? 1.8 : 1) * zoom}
              onClick={() => choose(marker.code)}
              onFocus={() => setHover(`${label(marker.code, marker.name)}. ${marker.note}`)}
              onMouseEnter={() => setHover(`${label(marker.code, marker.name)}. ${marker.note}`)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") { event.preventDefault(); choose(marker.code); }
                if (event.key === "ArrowRight") { event.preventDefault(); move(marker.code, 1); }
                if (event.key === "ArrowLeft") { event.preventDefault(); move(marker.code, -1); }
              }}
            />
          );
        })}
        {visiblePoints.map((point, index) => {
          const offset = (point.layer === "c2" ? 3 : -3) * zoom;
          const radius = ((point.layer === "c2" ? 3.4 : 2.2) + (point.count / maxPoint) * 2.8) * zoom;
          return (
            <g key={`${point.layer}-${point.country}`} className={`map-signal is-${point.layer}`} aria-hidden="true">
              <circle className="map-signal-halo" cx={point.at[0] + offset} cy={point.at[1] + offset} r={radius} style={{ animationDelay: `${(index % 11) * -0.41}s` }} />
              <circle className="map-signal-core" cx={point.at[0] + offset} cy={point.at[1] + offset} r={Math.max(1.2 * zoom, radius * 0.45)}>
                <title>{point.label}</title>
              </circle>
            </g>
          );
        })}
        {visibleFlows.map((flow, index) => {
          const d = flowPath(flow.from, flow.to);
          const width = (0.8 + (flow.value / maxFlow) * 2.8) * zoom;
          return (
            <g key={`${flow.origin}-${flow.target}-${index}`} className={"attack-path " + (flow.origin === flow.target ? "is-domestic" : "is-cross")} aria-hidden="true">
              <circle className="attack-path-origin" cx={flow.from[0]} cy={flow.from[1]} r={Math.min(4.5 * zoom, 1.8 * zoom + width * 0.45)} style={{ animationDelay: `${index * -0.23}s` }} />
              <path className="attack-path-base" d={d} fill="none" strokeWidth={width} />
              <path
                className="attack-path-pulse"
                d={d}
                fill="none"
                strokeWidth={Math.max(1.2 * zoom, width * 0.6)}
                pathLength={100}
                style={{ animationDelay: `${index * -0.37}s` }}
              />
              <circle className="attack-path-target" cx={flow.to[0]} cy={flow.to[1]} r={Math.min(5 * zoom, 2.2 * zoom + width * 0.6)} strokeWidth={0.8 * zoom} />
            </g>
          );
        })}
      </svg>
      {visibleFlows.length ? (
        <p className="sr-only">
          {visibleFlows.map((flow) => `${flow.originName} to ${flow.targetName}: ${flow.value}.`).join(" ")}
        </p>
      ) : null}
      {visiblePoints.length ? <p className="sr-only">{visiblePoints.map((point) => point.label).join(". ")}.</p> : null}
      {ready && unavailable.length ? (
        <p className="sr-only">
          No map shape for {unavailable.map((item) => `${publicCountryName(item.country, item.country)} (${item.count})`).join(", ")}. Values remain in the table.
        </p>
      ) : null}
    </div>
  );
}
