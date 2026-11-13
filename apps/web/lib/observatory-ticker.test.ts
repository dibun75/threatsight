import test from "node:test";
import assert from "node:assert/strict";

import { buildTicker } from "./observatory-ticker.ts";

test("ticker interleaves sources and keeps labels", () => {
  const rows = buildTicker(
    [{ indicator: "1.2.3.4", category: "ssh_scanning", country_code: "NL" }, { indicator: "5.6.7.8", category: "web_scanning" }],
    [{ indicator: "9.9.9.9:443", malware_family: "Cobalt Strike", category: "botnet_infrastructure" }],
  );
  assert.deepEqual(rows.map((row) => row.source), ["DShield", "ThreatFox", "DShield"]);
  assert.equal(rows[0].detail, "Ssh Scanning · NL");
  assert.equal(rows[1].detail, "Cobalt Strike");
});

test("ticker respects the limit and empty feeds", () => {
  assert.deepEqual(buildTicker([], []), []);
  const many = Array.from({ length: 50 }, (_, i) => ({ indicator: `ip${i}`, category: "scanning_source" }));
  assert.equal(buildTicker(many, many, 10).length, 10);
});
