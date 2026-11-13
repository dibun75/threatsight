import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: ["/", "/tour", "/briefing"],
        disallow: ["/api/", "/demo", "/threats", "/services", "/paths", "/controls", "/actions", "/evidence", "/ops", "/audit", "/systems", "/documents", "/discovery", "/exports", "/frameworks", "/requirements", "/showcase", "/governance", "/lab", "/reports"],
      },
    ],
    sitemap: "https://threatsight.io/sitemap.xml",
  };
}
