export type NavItem = { href: string; label: string; matches?: string[] };

export const PRIMARY_NAV: NavItem[] = [
  { href: "/demo", label: "Command center" },
  { href: "/threats", label: "Threat activity" },
  { href: "/services", label: "Exposure", matches: ["/services", "/paths", "/exposure"] },
  { href: "/actions", label: "Readiness", matches: ["/actions", "/controls", "/findings"] },
  { href: "/response", label: "Response" },
  { href: "/evidence", label: "Evidence" },
];

export const SUPPORT_NAV: NavItem[] = [
  { href: "/briefing", label: "Executive briefing" },
  { href: "/tour", label: "Guided tour" },
];

export const ADMIN_NAV: NavItem[] = [
  { href: "/agents", label: "AI agents" },
  { href: "/agents/fixes", label: "Guardrail fixes" },
  { href: "/compare", label: "Compare AI models" },
  { href: "/systems", label: "AI systems" },
  { href: "/requirements", label: "Requirements" },
  { href: "/documents", label: "Documents" },
  { href: "/frameworks", label: "Frameworks" },
  { href: "/threats/catalog", label: "Threat catalog" },
  { href: "/discovery", label: "Discovery" },
  { href: "/exports", label: "Reports" },
  { href: "/audit", label: "Audit" },
  { href: "/ops", label: "Operations checklist" },
  { href: "/access", label: "Access" },
  { href: "/integrations", label: "Integrations" },
  { href: "/settings", label: "Settings" },
  { href: "/showcase", label: "Guided demo" },
];

export const PUBLIC_NAV: NavItem[] = PRIMARY_NAV;

export const EXPOSURE_NAV: NavItem[] = [
  { href: "/exposure", label: "Overview" },
  { href: "/exposure/services", label: "Business services" },
  { href: "/exposure/assets", label: "Assets" },
  { href: "/exposure/paths", label: "Paths" },
  { href: "/exposure/matches", label: "Threat matches" },
  { href: "/exposure/connectors", label: "Connectors" },
];
