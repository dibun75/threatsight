export type TickerEntry = {
  key: string;
  source: "DShield" | "ThreatFox" | "Feodo" | "URLhaus";
  label: string;
  detail: string;
};

type DShieldRow = { indicator: string; category: string; country_code?: string | null };
type ThreatFoxRow = { indicator: string; malware_family?: string; threat_type?: string; category: string };

function words(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

/** Interleave the two independent public feeds. Rows stay source-labelled and are never merged or scored. */
type AbuseRow = { indicator: string; category: string; detail: string; country_code?: string | null; malware_family?: string; threat_type?: string };

export function buildTicker(dshield: DShieldRow[], threatfox: ThreatFoxRow[], limit = 24, feodo: AbuseRow[] = [], urlhaus: AbuseRow[] = []): TickerEntry[] {
  const left = dshield.map((item, index): TickerEntry => ({
    key: `d-${item.indicator}-${index}`,
    source: "DShield",
    label: item.indicator,
    detail: `${words(item.category)}${item.country_code ? ` · ${item.country_code}` : ""}`,
  }));
  const right = threatfox.map((item, index): TickerEntry => ({
    key: `t-${item.indicator}-${index}`,
    source: "ThreatFox",
    label: item.indicator,
    detail: item.malware_family || words(item.threat_type || item.category),
  }));
  const c2 = feodo.map((item, index): TickerEntry => ({
    key: `f-${item.indicator}-${index}`,
    source: "Feodo",
    label: item.indicator,
    detail: `${item.malware_family || "Botnet C2"}${item.country_code ? ` · ${item.country_code}` : ""}`,
  }));
  const urls = urlhaus.map((item, index): TickerEntry => ({
    key: `u-${item.indicator}-${index}`,
    source: "URLhaus",
    label: item.indicator.replace(/^https?:\/\//, ""),
    detail: words(item.threat_type || item.category),
  }));
  const lanes = [left, right, c2, urls];
  const out: TickerEntry[] = [];
  const longest = Math.max(0, ...lanes.map((lane) => lane.length));
  for (let i = 0; out.length < limit && i < longest; i += 1) {
    for (const lane of lanes) if (out.length < limit && i < lane.length) out.push(lane[i]);
  }
  return out;
}
