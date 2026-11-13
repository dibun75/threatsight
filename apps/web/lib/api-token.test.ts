import assert from "node:assert/strict";
import test from "node:test";

import { apiTokenFrom, upstreamHeaders } from "./bff-proxy.ts";

const good = "tsk_ab12cd34_" + "x".repeat(43);

test("only a well-formed read-only API token passes through the proxy", () => {
  assert.equal(apiTokenFrom(new Headers({ authorization: `Bearer ${good}` })), good);
  assert.equal(apiTokenFrom(new Headers({ authorization: "Bearer other-secret" })), "");
  assert.equal(apiTokenFrom(new Headers({ authorization: "Basic abc" })), "");
  assert.equal(apiTokenFrom(new Headers()), "");
  assert.equal(upstreamHeaders(new Headers({ authorization: `Bearer ${good}` })).get("authorization"), `Bearer ${good}`);
  assert.equal(upstreamHeaders(new Headers({ authorization: "Bearer not-a-token" })).get("authorization"), null);
});
