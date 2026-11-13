import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { changedStatement, comparison, navCurrent, presentation, reconcile, threatView } from "./experience.ts";

test("navigation selects threat activity and the catalog separately", () => {
  assert.equal(navCurrent("/threats", "/threats"), "page");
  assert.equal(navCurrent("/threats/advisories/1", "/threats"), "page");
  assert.equal(navCurrent("/threats/catalog", "/threats"), undefined);
  assert.equal(navCurrent("/threats/catalog", "/threats/catalog"), "page");
});

test("executive copy keeps the three data classes apart", () => {
  assert.equal(changedStatement(2), "Live public advisories matched to recorded assets: 2. Comparison unavailable.");
  assert.equal(comparison(null, 4), "Comparison unavailable.");
  assert.equal(comparison(4, 6), "+2 versus the previous equivalent period.");
  assert.equal(presentation("action_required"), "Action required");
  assert.equal(presentation("evidence_stale"), "More evidence required");
  assert.equal(presentation("verified_current"), "Monitoring / reference scenario");
  assert.equal(reconcile(3, 1), "Included 3. Excluded 1. Included plus excluded is 4.");
  assert.equal(threatView("activity"), "telemetry");
  assert.equal(threatView("world"), "advisory");
  assert.equal(threatView("emerging"), "emerging");
});

test("command center and threat activity state the limits in the interface", () => {
  const demo = readFileSync(new URL("../app/demo/page.tsx", import.meta.url), "utf8");
  const threats = readFileSync(new URL("../app/threats/page.tsx", import.meta.url), "utf8");
  const map = readFileSync(new URL("../components/command/HeroMap.tsx", import.meta.url), "utf8");
  const modes = readFileSync(new URL("./map-modes.ts", import.meta.url), "utf8");
  const experience = readFileSync(new URL("./experience.ts", import.meta.url), "utf8");
  const activity = readFileSync(new URL("../components/command/ActivityMap.tsx", import.meta.url), "utf8");
  const choropleth = readFileSync(new URL("../components/landscape/Choropleth.tsx", import.meta.url), "utf8");
  const shell = readFileSync(new URL("../components/AppShell.tsx", import.meta.url), "utf8");
  assert.match(demo, /Synthetic/);
  assert.match(demo, /ThreatObservatory/);
  assert.doesNotMatch(demo, /TelemetryBanner/);
  assert.match(map, /Global threat pulse/);
  assert.match(demo, /Unassigned/);
  assert.match(demo, /Open the service investigation/);
  const service = readFileSync(new URL("../app/services/[id]/page.tsx", import.meta.url), "utf8");
  assert.match(service, /No combined score|no combined score/);
  assert.match(service, /Unassigned/);
  assert.match(service, /Open the match/);
  assert.match(service, /Open the path/);
  assert.doesNotMatch(service, /proven packet delivery|confirmed compromise|control effectiveness/);
  assert.doesNotMatch(demo, /risk score/i);
  assert.match(modes, /Global observed activity/);
  assert.match(map, /Observed routes shown/);
  assert.match(map, /Leading observed path/);
  assert.match(map, /Cross-border/);
  assert.match(map, /Domestic/);
  assert.match(map, /Observed route ranking/);
  assert.match(map, /Top origins/);
  assert.match(map, /Top targets/);
  assert.match(map, /flows=\{flows\}/);
  assert.match(choropleth, /attack-path-pulse/);
  assert.match(demo, /Operational detail/);
  assert.doesNotMatch(modes, /attack activity/);
  assert.match(modes, /Advisory coverage/);
  assert.match(modes, /Your exposure/);
  assert.match(map, /No data returned/);
  assert.match(experience, /Comparison unavailable/);
  assert.match(map, /How to interpret this/);
  assert.doesNotMatch(map, /Cloudflare Radar not connected/);
  assert.doesNotMatch(demo, /Cloudflare Radar not connected/);
  assert.match(activity, /Observed attack telemetry unavailable/);
  assert.match(activity, /Synthetic demonstration — not live attack telemetry/);
  assert.match(activity, /Reference telemetry simulation/);
  assert.match(choropleth, /tabIndex=\{0\}/);
  assert.match(choropleth, /advisory-geography-tooltip/);
  assert.match(threats, /Emerging exploitation/);
  assert.match(threats, /Advisory activity/);
  assert.match(threats, /Organization relevance/);
  assert.match(threats, /Source health/);
  assert.match(demo, /Material exploitation changes/);
  assert.match(demo, /General news is excluded/);
  assert.match(shell, /Loading workspace/);
  assert.doesNotMatch(`${demo}\n${threats}\n${activity}`, /attacker attribution|packet reachability|control effectiveness/i);
});

test("guardrail fixes is its own nav item, not a sub-page of AI agents", () => {
  assert.equal(navCurrent("/agents/fixes", "/agents/fixes"), "page");
  assert.equal(navCurrent("/agents/fixes", "/agents"), undefined);
  assert.equal(navCurrent("/agents/report/x", "/agents"), "page");
});
