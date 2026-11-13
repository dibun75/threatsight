import type { NextConfig } from "next";

// The synthetic demo world (Nordvik, Helio) is a separate service with no database. Only the
// routes the Agents and Compare pages use are exposed; integrations are not. Changes to model
// connections, starting comparisons and changing the remediated policy are gated in middleware.ts.
const worldInternalUrl = process.env.WORLD_INTERNAL_URL || "http://localhost:8092";
const WORLD_ROUTES = ["profiles", "meta", "graph", "scenarios", "runs", "runs/:path*", "compare", "compare/:path*", "connections", "connections/:path*", "remediation", "remediation/:path*", "settings", "settings/:path*"];

const nextConfig: NextConfig = {
  output: "standalone",
  experimental: {
    // A live agent run (/api/world/runs) is synchronous; on a CPU-only local model it takes
    // several minutes, far past the 30 s default rewrite proxy timeout.
    proxyTimeout: 900_000,
  },
  async rewrites() {
    // beforeFiles: these must win over the catch-all /api/[...path] proxy to the main API.
    return {
      beforeFiles: WORLD_ROUTES.map((route) => ({
        source: `/api/world/${route}`,
        destination: `${worldInternalUrl}/api/world/${route}`,
      })),
      afterFiles: [],
      fallback: [],
    };
  },
  async redirects() {
    return [
      { source: "/sign-in", destination: "/login", permanent: false },
      { source: "/signin", destination: "/login", permanent: false },
      { source: "/radar", destination: "/threats", permanent: false },
      { source: "/landscape", destination: "/threats?view=world", permanent: false },
      { source: "/landscape/:id", destination: "/threats/advisories/:id", permanent: false },
      { source: "/exposure", destination: "/services", permanent: false },
      { source: "/assurance", destination: "/controls", permanent: false },
      { source: "/findings", destination: "/actions", permanent: false },
      { source: "/findings/:id", destination: "/actions/:id", permanent: false },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Content-Security-Policy", value: "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" },
          { key: "Cache-Control", value: "no-cache" },
        ],
      },
      {
        source: "/_next/static/:path*",
        headers: [{ key: "Cache-Control", value: "public, max-age=31536000, immutable" }],
      },
      {
        source: "/api/:path*",
        headers: [{ key: "Cache-Control", value: "no-store" }],
      },
    ];
  },
};

export default nextConfig;
