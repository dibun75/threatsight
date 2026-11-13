import { readFileSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";

const component = readFileSync(new URL("../components/command/ThreatObservatory.tsx", import.meta.url), "utf8");
const stage = readFileSync(new URL("../components/command/ObservatoryStage.tsx", import.meta.url), "utf8");

test("observatory keeps sources and meanings separate", () => {
  assert.match(stage, /Threat Observatory/);
  assert.match(stage, /Cloudflare Radar/);
  assert.match(stage, /not individual attacks, not customer traffic/);
  assert.match(component, /SANS ISC \/ DShield/);
  assert.match(component, /abuse\.ch ThreatFox/);
  assert.match(component, /Personal evaluation layer/);
  assert.match(component, /paid entitlement or written authorization/);
  assert.match(component, /Investigate one public IP/);
  assert.match(component, /not customer traffic/);
  assert.match(component, /not attacker attribution/);
  assert.match(component, /observationCount/);
  assert.match(component, /SourceTime value={item.last_seen}/);
});

test("observatory never calls an upstream feed from the browser", () => {
  assert.doesNotMatch(component, /feeds\.dshield\.org/);
  assert.doesNotMatch(component, /isc\.sans\.edu/);
  assert.match(component, /\/api\/v1\/telemetry\/observations/);
  assert.match(component, /observations\/threatfox/);
  assert.doesNotMatch(component, /threatfox-api\.abuse\.ch/);
  assert.doesNotMatch(component, /api\.greynoise\.io/);
});

test("observatory shows counters and a source-labelled public ticker", () => {
  assert.match(stage, /Top origins/);
  assert.match(stage, /Top targets/);
  assert.match(stage, /Top malware/);
  assert.match(component, /buildTicker/);
  assert.match(component, /feed=\{ticker\}/);
  assert.match(stage, /Reported indicators/);
  assert.doesNotMatch(stage, /Real-time attacks/i);
  assert.match(component, /Not customer traffic/i);
});

test("region windows stay inside the 800 x 400 map", async () => {
  const regions = [...stage.matchAll(/viewBox: "([\d ]+)"/g)].map((match) => match[1].split(" ").map(Number));
  assert.equal(regions.length, 8);
  for (const [x, y, width, height] of regions) {
    assert.ok(x >= 0 && y >= 0 && width > 0 && height > 0);
    assert.ok(x + width <= 800 && y + height <= 400);
  }
});

test("two-letter codes without a source name get a country name", async () => {
  const { publicCountryName } = await import("./country-names.ts");
  assert.equal(publicCountryName("AT", "AT"), "Austria");
  assert.equal(publicCountryName("US", "US"), "United States");
  assert.equal(publicCountryName("NO", "Norge"), "Norge");
  assert.equal(publicCountryName("ZZ9", "ZZ9"), "ZZ9");
});

test("zoomed map windows shrink marks so they keep their on-screen size", () => {
  const map = readFileSync(new URL("../components/landscape/Choropleth.tsx", import.meta.url), "utf8");
  const body = map.slice(map.indexOf("export function mapZoom"), map.indexOf("function flowPath"));
  const mapZoom = new Function(`${body.replace("export function mapZoom(viewBox: string): number", "function mapZoom(viewBox)")}; return mapZoom;`)() as (viewBox: string) => number;
  assert.equal(mapZoom("0 0 800 400"), 1);
  assert.equal(mapZoom("335 35 175 95"), 175 / 800);
  assert.equal(mapZoom("bad"), 1);
  assert.equal(mapZoom("0 0 1600 800"), 1);
  for (const sized of [/r=\{5 \* zoom\}/, /\* 2\.8\) \* zoom/, /2\.8\) \* zoom;/, /0\.4\) \* zoom/]) assert.match(map, sized);
  assert.match(stage, /function IndicatorFeed/);
});
