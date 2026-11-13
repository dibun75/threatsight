import assert from "node:assert/strict";
import test from "node:test";

import { safeRedirect } from "./proxy-policy.ts";

const authorization = "https://login.example/tenant/oauth2/v2.0/authorize";

test("login redirects stay on the configured authorization endpoint", () => {
  assert.equal(
    safeRedirect(["v1", "auth", "login"], `${authorization}?state=1`, authorization),
    true,
  );
  assert.equal(safeRedirect(["v1", "auth", "login"], "https://evil.example/authorize", authorization), false);
  assert.equal(safeRedirect(["v1", "auth", "login"], `${authorization}?state=1`, ""), false);
});

test("callback redirects are same-origin paths", () => {
  assert.equal(safeRedirect(["v1", "auth", "callback"], "/radar", authorization), true);
  assert.equal(safeRedirect(["v1", "auth", "callback"], "//evil.example", authorization), false);
  assert.equal(safeRedirect(["v1", "auth", "callback"], "https://threatsight.example/", authorization), false);
});
