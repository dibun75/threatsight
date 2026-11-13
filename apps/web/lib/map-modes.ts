export type MapMode = "activity" | "advisory" | "exposure";

export type MapModeConfig = {
  id: MapMode;
  title: string;
  metric: string;
  legend: string;
  interpretation: string;
};

export const MAP_MODES: Record<MapMode, MapModeConfig> = {
  activity: {
    id: "activity",
    title: "Global observed activity",
    metric: "Share of Cloudflare-observed mitigated Layer 7 requests",
    legend: "Share of Cloudflare-observed mitigated Layer 7 requests. Colour follows that percentage.",
    interpretation: "Global observations, not customer traffic.",
  },
  advisory: {
    id: "advisory",
    title: "Advisory coverage",
    metric: "Advisory-record count by publishing authority",
    legend: "Advisory-record count by publishing authority. This is coverage, not observed attacks.",
    interpretation: "Publisher jurisdiction, not an attacker or a target.",
  },
  exposure: {
    id: "exposure",
    title: "Your exposure",
    metric: "No geographic exposure verdict is available",
    legend: "No geographic exposure verdict is available. Country colour is not organization exposure.",
    interpretation: "Stored service evidence only. Geography is not a verdict.",
  },
};

export function legendLeak(mode: MapMode): string | null {
  const own = MAP_MODES[mode];
  for (const other of Object.values(MAP_MODES)) {
    if (other.id === mode) continue;
    if (own.legend.includes(other.metric) || own.metric.includes(other.metric)) return other.id;
  }
  return null;
}
