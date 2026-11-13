import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date("2026-11-01T00:00:00Z");
  return ["/", "/tour", "/briefing"].map((path) => ({
    url: `https://threatsight.io${path}`,
    lastModified: now,
    changeFrequency: "weekly",
    priority: path === "/" ? 1 : 0.4,
  }));
}
