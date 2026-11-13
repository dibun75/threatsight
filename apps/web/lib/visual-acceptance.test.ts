import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { publicCountryName } from "./country-names.ts";
import { matchLabel } from "./vocabulary.ts";
import { canonicalIso, reconcileAll, reconcileMeasurement, POINT_MARKERS } from "./country-geometry.ts";
import { MAP_MODES, legendLeak } from "./map-modes.ts";
import { loadingCopyIsNeutral, presentTelemetry, primaryAction, telemetryHeadline } from "./telemetry-state.ts";

test("telemetry presentation never calls a current snapshot disconnected", () => {
  assert.equal(presentTelemetry(null, true), "loading");
  assert.equal(presentTelemetry({ state: "current" }), "current");
  assert.equal(presentTelemetry({ state: "stale" }), "stale");
  assert.equal(presentTelemetry({ state: "failed_using_last_known_good" }), "failed_with_last_known_good");
  assert.equal(presentTelemetry({ state: "disabled" }), "disabled");
  assert.equal(presentTelemetry({ state: "failed_no_snapshot" }), "failed_without_snapshot");
  for (const state of ["current", "stale", "failed_with_last_known_good"] as const) {
    assert.doesNotMatch(telemetryHeadline(state), /not connected/i);
  }
  assert.equal(loadingCopyIsNeutral("Loading global activity."), true);
  assert.equal(loadingCopyIsNeutral("Cloudflare Radar not connected."), false);
  assert.match(telemetryHeadline("failed_with_last_known_good"), /latest refresh failed/i);
  assert.match(telemetryHeadline("disabled"), /not enabled/i);
});

test("map modes keep separate legends", () => {
  assert.equal(legendLeak("activity"), null);
  assert.equal(legendLeak("advisory"), null);
  assert.equal(legendLeak("exposure"), null);
  assert.equal(MAP_MODES.activity.title, "Global observed activity");
  assert.doesNotMatch(MAP_MODES.activity.title, /attack activity/i);
  assert.match(MAP_MODES.activity.legend, /Share of Cloudflare-observed/);
  assert.match(MAP_MODES.advisory.legend, /Advisory-record count/);
  assert.match(MAP_MODES.exposure.legend, /No geographic exposure verdict/);
  assert.doesNotMatch(MAP_MODES.activity.legend, /Advisory-record count/);
  assert.doesNotMatch(MAP_MODES.advisory.legend, /Share of Cloudflare-observed/);
  assert.doesNotMatch(MAP_MODES.exposure.legend, /Advisory-record count|Share of Cloudflare-observed/);
});

test("country geometry resolves polygons, markers, and explicit gaps", () => {
  const document = JSON.parse(readFileSync(new URL("../public/geo/ne_110m_admin_0_countries.geojson", import.meta.url), "utf8")) as {
    features: { properties: { iso_a2: string; name: string } }[];
  };
  const polygons = new Set(document.features.flatMap((feature) => {
    const iso = canonicalIso(feature.properties);
    return iso ? [iso] : [];
  }));
  assert.equal(reconcileMeasurement("NO", polygons), "polygon");
  assert.equal(reconcileMeasurement("FR", polygons), "polygon");
  assert.equal(reconcileMeasurement("TW", polygons), "polygon");
  assert.equal(reconcileMeasurement("XK", polygons), "polygon");
  assert.equal(reconcileMeasurement("SG", polygons), "marker");
  assert.equal(reconcileMeasurement("HK", polygons), "marker");
  assert.equal(reconcileMeasurement("GG", polygons), "marker");
  assert.equal(POINT_MARKERS.SG.lon > 100, true);
  const measured = ["NO", "FR", "US", "SG", "HK", "GG", "ZZ"];
  const outcomes = reconcileAll(measured, polygons);
  assert.equal(outcomes.length, measured.length);
  assert.deepEqual(outcomes.map((item) => item.outcome), ["polygon", "polygon", "polygon", "marker", "marker", "marker", "unavailable"]);
});

test("the primary action stays concrete", () => {
  assert.equal(
    primaryAction("Decide whether to validate the installed product version and assign an owner for the missing control evidence."),
    "Validate the installed version and assign an owner.",
  );
});

test("public country labels keep the ISO code and say United States", () => {
  assert.equal(matchLabel("confirmed_identifier_match").label, "Identifier match");
  assert.equal(matchLabel("Identifier match").label, "Identifier match");
  assert.equal(matchLabel("not_a_state").label, "Unknown state");
  assert.equal(publicCountryName("US", "United States of America"), "United States");
  assert.equal(publicCountryName("NO", "Norway"), "Norway");
});

test("the closed country selector does not fall back to the first option", () => {
  const map = readFileSync(new URL("../components/command/HeroMap.tsx", import.meta.url), "utf8");
  assert.match(map, /Loading countries/);
  assert.match(map, /disabled=\{countries\.length === 0\}/);
});

test("the mobile menu target is at least 44 pixels", () => {
  const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(css, /\.nav-toggle \{[\s\S]*min-width: 44px;[\s\S]*min-height: 44px;/);
  assert.match(css, /\.nav a \{[\s\S]*min-height: 44px;/);
  assert.match(css, /\.nav-more \{[\s\S]*min-height: 44px;/);
});

test("control-library filters present assurance vocabulary", () => {
  const page = readFileSync(new URL("../app/controls/page.tsx", import.meta.url), "utf8");
  assert.match(page, /presentedValue\(item\)/);
  assert.match(page, /presentedValue\("PASS"\)/);
  assert.match(page, /presentedValue\(item\.assurance_status\)/);
  assert.doesNotMatch(page, />\s*VALIDATED\s*</);
});

test("the command center keeps the decision chain and no combined score", () => {
  const demo = readFileSync(new URL("../app/demo/page.tsx", import.meta.url), "utf8");
  const briefing = readFileSync(new URL("../app/briefing/page.tsx", import.meta.url), "utf8");
  const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
  const order = ["Global observations", "Organization relevance", "Business service", "Candidate exposure", "Control readiness", "Required action"];
  let cursor = 0;
  for (const label of order) {
    const next = demo.indexOf(label, cursor);
    assert.equal(next > cursor, true, label);
    cursor = next;
  }
  assert.doesNotMatch(demo, /risk score|combined score/i);
  assert.match(briefing, /Current decision/);
  const decisionAt = briefing.indexOf("Current decision");
  assert.equal(decisionAt > 0 && decisionAt < briefing.indexOf("briefing-later"), true);
  assert.match(briefing, /What remains uncertain/);
  assert.match(css, /briefing-later \{ break-before: page; \}/);
  const tour = readFileSync(new URL("../app/tour/page.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(tour, /Fixture|credential_required|synthetic-correlation|:software/);
  const servicePage = readFileSync(new URL("../app/services/[id]/page.tsx", import.meta.url), "utf8");
  assert.match(servicePage, /commercialTitle\(threat\.title\)/);
  assert.match(servicePage, /Technical details/);
  assert.match(css, /@media print[\s\S]*\.briefing h1/);
  assert.match(readFileSync(new URL("../app/findings/page.tsx", import.meta.url), "utf8"), /Clear filters/);
});

test("commercial copy does not show the fixture maturity label", () => {
  const files = [
    "../app/demo/page.tsx",
    "../app/briefing/page.tsx",
    "../app/tour/page.tsx",
    "../app/services/[id]/page.tsx",
    "../app/evidence/page.tsx",
    "../app/landscape/page.tsx",
    "../components/Overview.tsx",
    "../components/TruthMark.tsx",
    "../components/exposure/Phase2.tsx",
    "../lib/vocabulary.ts",
  ];
  for (const file of files) {
    const source = readFileSync(new URL(file, import.meta.url), "utf8");
    const visible = [...source.matchAll(/`(?:\\.|[^`])*`|"(?:\\.|[^"])*"|'(?:\\.|[^'])*'/g)]
      .map((match) => match[0].replace(/\$\{[^}]+\}/g, ""))
      .join("\n")
      .replaceAll('"fixture_tested"', "")
      .replaceAll("'fixture_tested'", "");
    assert.doesNotMatch(visible, /Fixture tested|fixture tested|fixture_tested|fixture-tested/i, file);
  }
  assert.match(readFileSync(new URL("../app/services/[id]/page.tsx", import.meta.url), "utf8"), /maturityStatement\(path\.maturity\)/);
  assert.match(readFileSync(new URL("../app/services/[id]/page.tsx", import.meta.url), "utf8"), /scrubReferenceText\(step\.from\)/);
  assert.match(readFileSync(new URL("../lib/vocabulary.ts", import.meta.url), "utf8"), /Validated with reference data/);
  assert.match(readFileSync(new URL("../lib/vocabulary.ts", import.meta.url), "utf8"), /Synthetic/);
});

test("service tabs and the action register keep context in the URL", () => {
  const service = readFileSync(new URL("../app/services/[id]/page.tsx", import.meta.url), "utf8");
  const actions = readFileSync(new URL("../app/findings/page.tsx", import.meta.url), "utf8");
  const demo = readFileSync(new URL("../app/demo/page.tsx", import.meta.url), "utf8");
  assert.match(service, /tab/);
  assert.match(service, /service=\$\{params\.id\}/);
  assert.match(actions, /Filtered to this service/);
  assert.match(demo, /Loading global activity|Loading the priority service|Loading the next action/);
  assert.doesNotMatch(demo, /No decision is recorded|Evidence completeness is not loaded|Cloudflare Radar not connected/);
});
