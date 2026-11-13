import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import test from "node:test";

import { browserResponseHeaders, upstreamHeaders } from "./bff-proxy.ts";

const require = createRequire(import.meta.url);

test("logout forwarding keeps the browser origin, CSRF, and cookie expiry", () => {
  const route = readFileSync(new URL("../app/api/[...path]/route.ts", import.meta.url), "utf8");
  assert.match(route, /upstreamHeaders/);
  assert.match(route, /method: request\.method/);
  assert.match(route, /redirect: "manual"/);
  const headers = upstreamHeaders(new Headers({
    origin: "https://threatsight.io",
    cookie: "threatsight_session=present; threatsight_csrf=matching",
    "x-csrf-token": "matching",
    "content-type": "application/json",
  }));
  assert.equal(headers.get("origin"), "https://threatsight.io");
  assert.equal(headers.get("x-csrf-token"), "matching");
  assert.match(headers.get("cookie") ?? "", /threatsight_session=present/);
  const upstream = new Headers({ "set-cookie": "threatsight_session=; Max-Age=0; Path=/; HttpOnly" });
  const outgoing = browserResponseHeaders(204, upstream);
  assert.match((outgoing.get("set-cookie") ?? "").toLowerCase(), /max-age=0/);
  assert.equal(outgoing.get("cache-control"), "no-store");
  const { toNodeOutgoingHttpHeaders } = require("next/dist/server/web/utils.js") as {
    toNodeOutgoingHttpHeaders: (headers: Headers) => Record<string, string | string[]>;
  };
  const many = new Headers();
  for (const name of ["threatsight_session", "__Host-threatsight_session", "threatsight_csrf"]) {
    many.append("set-cookie", `${name}=""; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; HttpOnly; SameSite=lax`);
  }
  const forwarded = toNodeOutgoingHttpHeaders(browserResponseHeaders(204, many))["set-cookie"];
  const list = Array.isArray(forwarded) ? forwarded : [forwarded];
  assert.equal(list.length, 3);
  assert.ok(list.every((item) => item.includes("1970") && item.includes("Max-Age=0")));
});
