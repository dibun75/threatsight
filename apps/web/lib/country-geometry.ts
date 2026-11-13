export type GeometryOutcome = "polygon" | "marker" | "unavailable";

export type Marker = { code: string; name: string; lon: number; lat: number; note: string };

/** Natural Earth 110m uses -99 or a non-ISO code for these polygons. The name is the reviewed alias. */
const POLYGON_NAME_TO_ISO: Record<string, string> = {
  Norway: "NO",
  France: "FR",
  Kosovo: "XK",
  Taiwan: "TW",
};

const POLYGON_CODE_TO_ISO: Record<string, string> = {
  "CN-TW": "TW",
};

/**
 * Centroids for territories absent from Natural Earth 1:110m.
 * These are point markers, not borrowed polygons.
 * Singapore and Hong Kong: Natural Earth populated-places centroids.
 * Guernsey: Gazetteer centroid for the island, approximately 49.45N 2.59W.
 */
export const POINT_MARKERS: Record<string, Marker> = {
  SG: { code: "SG", name: "Singapore", lon: 103.8198, lat: 1.3521, note: "Point marker. This dataset has no Singapore polygon." },
  HK: { code: "HK", name: "Hong Kong", lon: 114.1694, lat: 22.3193, note: "Point marker. This dataset has no Hong Kong polygon." },
  GG: { code: "GG", name: "Guernsey", lon: -2.585, lat: 49.454, note: "Point marker. This dataset has no Guernsey polygon." },
};

export function canonicalIso(properties: { iso_a2?: string | null; name?: string | null }): string | null {
  const code = properties.iso_a2 ?? "";
  const name = properties.name ?? "";
  if (code && code !== "-99") {
    if (POLYGON_CODE_TO_ISO[code]) return POLYGON_CODE_TO_ISO[code];
    return /^[A-Z]{2}$/.test(code) ? code : null;
  }
  return POLYGON_NAME_TO_ISO[name] ?? null;
}

export function reconcileMeasurement(code: string, polygons: ReadonlySet<string>): GeometryOutcome {
  if (polygons.has(code)) return "polygon";
  if (POINT_MARKERS[code]) return "marker";
  return "unavailable";
}

export function reconcileAll(codes: readonly string[], polygons: ReadonlySet<string>): { code: string; outcome: GeometryOutcome }[] {
  return codes.map((code) => ({ code, outcome: reconcileMeasurement(code, polygons) }));
}
