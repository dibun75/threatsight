import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { JSDOM } from "jsdom";

const origin = process.env.THREATSIGHT_WEB_ORIGIN || "http://127.0.0.1:3001";
const axeSource = readFileSync(new URL("../node_modules/axe-core/axe.js", import.meta.url), "utf8");
const routes = [
  "/",
  "/login",
  "/demo",
  "/threats",
  "/services",
  "/services/1e8f355e-a755-4dbf-b4a1-7c83c4e5e56a",
  "/paths",
  "/briefing",
  "/controls",
  "/actions",
  "/radar",
  "/landscape",
  "/exposure",
  "/exposure/services",
  "/exposure/services/1e8f355e-a755-4dbf-b4a1-7c83c4e5e56a",
  "/exposure/assets",
  "/exposure/paths",
  "/exposure/paths/5a2be1e0-eef7-4122-a31b-ccd8593aebb0",
  "/exposure/matches",
  "/exposure/matches/49c4be2c-8657-4327-ab89-a7071ee24799",
  "/exposure/connectors",
  "/assurance",
  "/findings",
  "/evidence",
  "/tour",
  "/ops",
];

async function scan(path) {
  const response = await fetch(`${origin}${path}`);
  assert.equal(response.status, 200, path);
  const html = await response.text();
  const dom = new JSDOM(html, { url: `${origin}${path}`, runScripts: "dangerously", pretendToBeVisual: true });
  dom.window.HTMLCanvasElement.prototype.getContext = () => ({
    measureText: (text) => ({ width: String(text).length * 8 }),
    font: "",
  });
  dom.window.eval(axeSource);
  const result = await dom.window.axe.run(dom.window.document, {
    resultTypes: ["violations"],
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa"] },
  });
  const blocking = result.violations.filter((item) => item.impact === "serious" || item.impact === "critical");
  const ids = Array.from(blocking, (item) => `${item.id}:${item.impact}`);
  if (ids.length) {
    throw new Error(`${path} ${ids.join(",")}`);
  }
}

test("server HTML on the reference routes has no serious or critical axe findings", async () => {
  for (const path of routes) {
    await scan(path);
  }
});
