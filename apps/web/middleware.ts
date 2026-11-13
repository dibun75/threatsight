import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { browserFacingOrigin } from "./lib/browser-origin";
import { apiTokenFrom } from "./lib/bff-proxy";

const PUBLIC_PAGES = new Set(["/login", "/activate", "/reset"]);
const PUBLIC_FILES = new Set(["/favicon.svg", "/og.svg", "/robots.txt", "/sitemap.xml"]);

function isPublic(path: string): boolean {
  if (PUBLIC_PAGES.has(path) || PUBLIC_FILES.has(path)) return true;
  if (
    path.startsWith("/_next/")
    || path.startsWith("/api/v1/auth/login")
    || path.startsWith("/api/v1/auth/callback")
    || path.startsWith("/api/v1/auth/status")
    || path.startsWith("/api/v1/auth/local/login")
    || path.startsWith("/api/v1/auth/local/activate")
    || path.startsWith("/api/v1/auth/local/reset")
  ) {
    return true;
  }
  return path === "/health" || path === "/ready" || path === "/api/health" || path === "/api/ready";
}

function retireLegacyCookies(response: NextResponse): NextResponse {
  const expires = "Thu, 01 Jan 1970 00:00:00 GMT";
  const names = ["threatsight_session", "threatsight_csrf", "threatsight_oidc"];
  for (const name of names) {
    const httpOnly = name === "threatsight_csrf" ? "" : "; HttpOnly";
    response.headers.append("set-cookie", `${name}=; Max-Age=0; Expires=${expires}; Path=/; SameSite=Lax${httpOnly}`);
    response.headers.append("set-cookie", `${name}=; Max-Age=0; Expires=${expires}; Path=/; Secure; SameSite=Lax${httpOnly}`);
  }
  return response;
}

function redirectTo(request: NextRequest, pathname: string, search: string): NextResponse {
  const origin = browserFacingOrigin({
    nextOrigin: request.nextUrl.origin,
    nextHost: request.nextUrl.host,
    host: request.headers.get("host"),
    forwardedHost: request.headers.get("x-forwarded-host"),
    forwardedProto: request.headers.get("x-forwarded-proto"),
    protocol: request.nextUrl.protocol,
  });
  const destination = new URL(pathname, origin);
  destination.search = search;
  const redirect = NextResponse.redirect(destination);
  redirect.headers.set("cache-control", "no-store");
  return redirect;
}

const WORLD_CONNECTIONS = /^\/api\/world\/(connections|settings)(\/|$)/;
const WORLD_COMPARE = /^\/api\/world\/compare(\/|$)/;
const WORLD_REMEDIATION = /^\/api\/world\/remediation(\/|$)/;
const ADMIN_ROLES = new Set(["platform-admin", "workspace-admin", "admin"]);
const OPERATOR_ROLES = new Set(["operator", "reviewer", ...ADMIN_ROLES]);

function denied(status: number, detail: string): NextResponse {
  return NextResponse.json({ detail }, { status, headers: { "cache-control": "no-store" } });
}

// Model connections and model settings decide where the demo-world service connects (and hold keys), and a comparison spends model time.
// Both are closed in the public demonstration; otherwise connections need an administrator and
// starting or changing a comparison needs an operator. Reading comparison results stays open.
// Proposing, applying, rejecting or rolling back a remediation also needs an operator: the approver
// named on the request is recorded, so the person behind it must be signed in.
async function guardWorld(request: NextRequest, mode: string | undefined): Promise<NextResponse | null> {
  const path = request.nextUrl.pathname;
  const connections = WORLD_CONNECTIONS.test(path);
  const write = !["GET", "HEAD", "OPTIONS"].includes(request.method);
  const compareWrite = WORLD_COMPARE.test(path) && write;
  const fixWrite = WORLD_REMEDIATION.test(path) && write;
  if (!connections && !compareWrite && !fixWrite) return null;
  if (mode !== "oidc" && mode !== "local") return denied(403, "Not available in the public demonstration");
  let role = "";
  try {
    const base = process.env.API_INTERNAL_URL || "http://localhost:8000";
    const session = await fetch(new URL("/api/v1/auth/session", base), {
      headers: { cookie: request.headers.get("cookie") || "", accept: "application/json" },
      cache: "no-store",
    });
    if (session.status === 200) role = String((await session.json()).role || "");
  } catch {
    role = "";
  }
  if (!role) return denied(401, "Authentication required");
  const allowed = connections ? ADMIN_ROLES : OPERATOR_ROLES;
  return allowed.has(role) ? null : denied(403, connections ? "Only an administrator can change model connections and settings" : fixWrite ? "Your role cannot change guardrail fixes" : "Your role cannot start comparisons");
}

export async function middleware(request: NextRequest) {
  const mode = process.env.THREATSIGHT_AUTH_MODE;
  const blocked = await guardWorld(request, mode);
  if (blocked) return blocked;
  if (mode !== "oidc" && mode !== "local") return NextResponse.next();
  const path = request.nextUrl.pathname;
  // A read-only API token is checked by the API itself (it refuses writes and owner routes), so the
  // proxy only lets a well-formed one through for reads.
  if (path.startsWith("/api/") && apiTokenFrom(request.headers)) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return NextResponse.json({ detail: "API tokens are read-only" }, { status: 403, headers: { "cache-control": "no-store" } });
    }
    return NextResponse.next();
  }
  if (isPublic(path)) return NextResponse.next();
  if (request.cookies.get("threatsight_session")?.value || request.cookies.get("__Host-threatsight_session")?.value) {
    const base = process.env.API_INTERNAL_URL || "http://localhost:8000";
    let authorized = false;
    try {
      const session = await fetch(new URL("/api/v1/auth/session", base), {
        headers: { cookie: request.headers.get("cookie") || "", accept: "application/json" },
        cache: "no-store",
      });
      authorized = session.status === 200;
    } catch {
      authorized = false;
    }
    if (!authorized) {
      if (path === "/api/v1/auth/logout") {
        const allowed = NextResponse.next();
        allowed.headers.set("cache-control", "no-store");
        return allowed;
      }
      if (path.startsWith("/api/")) {
        return retireLegacyCookies(NextResponse.json({ detail: "Authentication required" }, { status: 401, headers: { "cache-control": "no-store" } }));
      }
      return retireLegacyCookies(redirectTo(request, "/login", "reason=expired"));
    }
    const allowed = NextResponse.next();
    allowed.headers.set("cache-control", "no-store");
    return allowed;
  }
  if (path.startsWith("/api/")) {
    return NextResponse.json({ detail: "Authentication required" }, { status: 401, headers: { "cache-control": "no-store" } });
  }
  const returnTo = `${path}${request.nextUrl.search}`;
  const safeReturn = returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/";
  return redirectTo(request, "/login", `return_to=${encodeURIComponent(safeReturn)}`);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image).*)"],
};
