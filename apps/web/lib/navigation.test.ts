import assert from "node:assert/strict";
import test from "node:test";

import { ADMIN_NAV, EXPOSURE_NAV, PRIMARY_NAV, PUBLIC_NAV, SUPPORT_NAV } from "./navigation.ts";
import { displayText, vocabularyAvoidsForbiddenClaims } from "./vocabulary.ts";

test("core navigation is outcome-oriented", () => {
  assert.deepEqual(PRIMARY_NAV.map((item) => item.label), ["Command center", "Threat activity", "Exposure", "Readiness", "Response", "Evidence"]);
  assert.deepEqual(PRIMARY_NAV.find((item) => item.label === "Exposure")?.matches, ["/services", "/paths", "/exposure"]);
  assert.deepEqual(PRIMARY_NAV.find((item) => item.label === "Readiness")?.matches, ["/actions", "/controls", "/findings"]);
  assert.equal(ADMIN_NAV.some((item) => item.href === "/controls"), false);
});

test("exposure sections exist and actions stay on findings", () => {
  assert.deepEqual(EXPOSURE_NAV.map((item) => item.href), [
    "/exposure",
    "/exposure/services",
    "/exposure/assets",
    "/exposure/paths",
    "/exposure/matches",
    "/exposure/connectors",
  ]);
  assert.equal(PRIMARY_NAV.find((item) => item.label === "Readiness")?.href, "/actions");
  assert.deepEqual(SUPPORT_NAV.map((item) => item.href), ["/briefing", "/tour"]);
  assert.equal(PUBLIC_NAV.at(-1)?.href, "/evidence");
  assert.equal(PUBLIC_NAV.some((item) => item.href === "/ops"), false);
});

test("match copy avoids incident claims and strips markup", () => {
  assert.equal(vocabularyAvoidsForbiddenClaims(), true);
  assert.equal(displayText("<script>alert(1)</script>"), "scriptalert(1)/script");
  assert.equal(displayText("a".repeat(400)).length, 180);
});
