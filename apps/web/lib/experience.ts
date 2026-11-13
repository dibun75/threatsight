export const DATA_CLASSES = ["Live public advisory intelligence", "Synthetic enterprise evidence", "Observed attack telemetry"] as const;

export function navCurrent(pathname: string, href: string): "page" | undefined {
  if (href === "/") return pathname === "/" ? "page" : undefined;
  if (href === "/exposure") return pathname === "/exposure" ? "page" : undefined;
  if (href === "/agents" && pathname.startsWith("/agents/fixes")) return undefined;
  if (href === "/threats") {
    if (pathname === "/threats") return "page";
    if (pathname.startsWith("/threats/") && !pathname.startsWith("/threats/catalog")) return "page";
    return undefined;
  }
  if (pathname === href || pathname.startsWith(`${href}/`)) return "page";
  return undefined;
}

export function changedStatement(liveCount: number): string {
  return `Live public advisories matched to recorded assets: ${liveCount}. Comparison unavailable.`;
}

export function comparison(previous: number | null, current: number): string {
  if (previous === null) return "Comparison unavailable.";
  const delta = current - previous;
  if (delta === 0) return "Unchanged versus the previous equivalent period.";
  return `${delta > 0 ? "+" : ""}${delta} versus the previous equivalent period.`;
}

export function presentation(state: string): "Action required" | "More evidence required" | "Monitoring / reference scenario" {
  if (state === "action_required") return "Action required";
  if (state === "verified_current" || state === "no_current_relevant_match") return "Monitoring / reference scenario";
  return "More evidence required";
}

export const MEASUREMENT: Record<string, string> = {
  authority_jurisdiction: "Count of current advisories whose source names this country as the reporting-authority jurisdiction.",
  affected_jurisdiction: "Count of current advisories that explicitly name this country as an affected jurisdiction.",
  advisory_jurisdiction: "Count of current advisories whose source states this country as coverage.",
};

export function reconcile(included: number, excluded: number): string {
  return `Included ${included}. Excluded ${excluded}. Included plus excluded is ${included + excluded}.`;
}

const VIEWS: Record<string, "emerging" | "advisory" | "relevance" | "telemetry" | "sources"> = {
  emerging: "emerging",
  exploitation: "emerging",
  advisory: "advisory",
  world: "advisory",
  timeline: "advisory",
  relevance: "relevance",
  relevant: "relevance",
  telemetry: "telemetry",
  activity: "telemetry",
  sources: "sources",
};

export function threatView(value: string | null): "emerging" | "advisory" | "relevance" | "telemetry" | "sources" {
  return VIEWS[value || ""] ?? "relevance";
}
