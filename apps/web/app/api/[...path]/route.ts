import { NextRequest, NextResponse } from "next/server";

import { browserResponseHeaders, upstreamHeaders } from "../../../lib/bff-proxy";
import { safeRedirect } from "../../../lib/proxy-policy";

const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  if (!ALLOWED_METHODS.has(request.method)) {
    return new Response("Method not allowed", { status: 405 });
  }

  const base = process.env.API_INTERNAL_URL || "http://localhost:8000";
  const parsedBase = new URL(base);
  if (!["http:", "https:"].includes(parsedBase.protocol)) {
    return new Response("Invalid internal API configuration", { status: 500 });
  }

  const { path } = await context.params;
  const target = new URL(`/api/${path.map(encodeURIComponent).join("/")}`, parsedBase);
  target.search = request.nextUrl.search;

  const headers = upstreamHeaders(request.headers);

  const token = (process.env.API_INTERNAL_TOKEN || "").trim();
  const subject = (process.env.API_INTERNAL_SUBJECT || "").trim();
  if (process.env.THREATSIGHT_AUTH_MODE === "oidc" || process.env.THREATSIGHT_AUTH_MODE === "local") {
    // The browser session cookie is forwarded. Do not invent an actor.
  } else if (token) {
    headers.set("authorization", `Bearer ${token}`);
  } else if (process.env.NODE_ENV !== "production" || subject) {
    headers.set("x-actor", subject || "demo-viewer");
    headers.set("x-role", process.env.API_INTERNAL_ROLE || "viewer");
  }

  const hasBody = !["GET", "HEAD"].includes(request.method);
  const response = await fetch(target, {
    method: request.method,
    headers,
    body: hasBody ? await request.arrayBuffer() : undefined,
    redirect: "manual",
    cache: "no-store",
  });

  const location = response.headers.get("location");
  if (location && [301, 302, 303, 307, 308].includes(response.status)) {
    const authorization = process.env.THREATSIGHT_OIDC_AUTHORIZATION_ENDPOINT || "";
    if (!safeRedirect(path, location, authorization)) {
      return new Response("Unsafe redirect", { status: 502 });
    }
  }

  const outgoing = browserResponseHeaders(response.status, response.headers);
  const next = new NextResponse(response.body, { status: response.status });
  outgoing.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") return;
    next.headers.set(key, value);
  });
  for (const cookie of outgoing.getSetCookie()) next.headers.append("set-cookie", cookie);
  return next;
}

export const dynamic = "force-dynamic";
export { proxy as GET, proxy as POST, proxy as PUT, proxy as PATCH, proxy as DELETE, proxy as HEAD, proxy as OPTIONS };
