import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { browserFacingOrigin } from "./browser-origin.ts";
import { dataContextLabel, identityLines, initials, roleLabel, safeContinuePath } from "./session.ts";

test("session presentation uses canonical roles and does not invent a switcher", () => {
  assert.equal(roleLabel("viewer"), "Viewer");
  assert.equal(roleLabel("operator"), "Operator");
  assert.equal(roleLabel("platform-admin"), "Platform administrator");
  assert.equal(dataContextLabel("Synthetic reference"), "Synthetic reference");
  assert.equal(dataContextLabel("development"), "Reference data");
  assert.equal(initials("Ada Lovelace"), "AL");
  assert.deepEqual(identityLines("owner@example.com", "owner@example.com"), { name: "", account: "owner@example.com" });
  assert.deepEqual(identityLines("Ada Lovelace", "ada@example.com"), { name: "Ada Lovelace", account: "ada@example.com" });
});

test("shell exposes workspace and logout without a secret", () => {
  const shell = readFileSync(new URL("../components/AppShell.tsx", import.meta.url), "utf8");
  const logout = readFileSync(new URL("./logout.ts", import.meta.url), "utf8");
  const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
  const findings = readFileSync(new URL("../app/findings/page.tsx", import.meta.url), "utf8");
  const middleware = readFileSync(new URL("../middleware.ts", import.meta.url), "utf8");
  assert.match(shell, /workspace-block/);
  assert.match(shell, /account-block/);
  assert.match(shell, /Log out/);
  assert.doesNotMatch(shell, /method:\s*"GET"/);
  assert.match(css, /@media \(max-width: 900px\)/);
  assert.match(css, /\.account-block/);
  assert.match(findings, /Actions/);
  assert.match(middleware, /no-store/);
  assert.match(middleware, /retireLegacyCookies/);
  assert.match(middleware, /01 Jan 1970/);
  assert.match(shell, /aria-label="Account"/);
  assert.match(logout, /method: "POST"/);
  assert.match(logout, /\/api\/v1\/auth\/logout/);
  assert.match(logout, /\/api\/v1\/auth\/session/);
  assert.match(shell, /Data context/);
  assert.match(shell, /Workspace/);
  assert.doesNotMatch(shell, /environmentLabel/);
  const login = readFileSync(new URL("../app/login/page.tsx", import.meta.url), "utf8");
  assert.match(login, /autoComplete="username"/);
  assert.match(login, /autoComplete="current-password"/);
  assert.match(login, /Already signed in/);
  assert.match(login, /Show password/);
  assert.match(css, /min-height: 44px/);
  assert.match(css, /max-width: 390px/);
  assert.match(css, /prefers-reduced-motion/);
});

test("auth redirects keep the browser host", () => {
  const loopback = {
    nextOrigin: "http://localhost:3000",
    nextHost: "localhost:3000",
    host: "127.0.0.1:3001",
    forwardedHost: null,
    forwardedProto: null,
    protocol: "http:",
  };
  assert.equal(browserFacingOrigin(loopback), "http://127.0.0.1:3001");
  assert.equal(
    browserFacingOrigin({ ...loopback, host: "evil.example", forwardedHost: "evil.example" }),
    "http://localhost:3000",
  );
  assert.equal(
    browserFacingOrigin({
      ...loopback,
      nextOrigin: "https://threatsight.io",
      nextHost: "threatsight.io",
      host: "threatsight.io",
      forwardedProto: "https",
    }),
    "https://threatsight.io",
  );
});

test("login continuation stays on the site", () => {
  assert.equal(safeContinuePath("/demo"), "/demo");
  assert.equal(safeContinuePath("https://evil.example"), "/demo");
  assert.equal(safeContinuePath("//evil.example"), "/demo");
  assert.equal(safeContinuePath("/login"), "/demo");
  assert.equal(safeContinuePath(null), "/demo");
});
