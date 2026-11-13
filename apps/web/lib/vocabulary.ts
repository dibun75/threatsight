export type TruthKey =
  | "synthetic"
  | "fixture_tested"
  | "live_verified"
  | "observed"
  | "configured"
  | "inferred"
  | "manual"
  | "partial"
  | "stale"
  | "unknown"
  | "conflicting"
  | "unsupported"
  | "replayed_snapshot"
  | "credential_required";

export const TRUTH: Record<TruthKey, { label: string; description: string }> = {
  synthetic: { label: "Synthetic", description: "Constructed reference data. It is not a customer record." },
  fixture_tested: { label: "Validated with reference data", description: "Tested against controlled synthetic data. A live customer environment has not been validated." },
  live_verified: { label: "Live verified", description: "A live collection was recorded for this workspace." },
  observed: { label: "Observed", description: "The source reported this fact from collection, not only from configuration." },
  configured: { label: "Configured", description: "The source reported intended configuration. This is not observed packet delivery." },
  inferred: { label: "Inferred", description: "The product derived this from other records. It was not directly observed." },
  manual: { label: "Manual", description: "An operator recorded this relationship." },
  partial: { label: "Partial", description: "Collection or analysis stopped before the scope was complete." },
  stale: { label: "Stale", description: "The source or snapshot is older than its freshness rule." },
  unknown: { label: "Unknown", description: "A required fact is missing or cannot be ordered safely." },
  conflicting: { label: "Conflicting", description: "Sources disagree. Both claims stay visible." },
  unsupported: { label: "Unsupported", description: "This product cannot evaluate the reported format or capability." },
  replayed_snapshot: { label: "Replayed snapshot", description: "This run used a completed snapshot that is no longer the current snapshot." },
  credential_required: { label: "Credentials required", description: "Live validation needs credentials. None are recorded here." },
};

export const SOURCE_LABELS: Record<string, string> = {
  "synthetic-correlation": "Synthetic reference evidence",
  "synthetic-fixture": "Synthetic reference evidence",
};

export function commercialTitle(title: string): string {
  return title.replace(/^Fixture\s+/i, "").trim();
}

export const ASSURANCE_LABELS: Record<string, string> = {
  VALIDATED: "Validated",
  PARTIALLY_VALIDATED: "Partially validated",
  GAP_DETECTED: "Gap detected",
  EVIDENCE_REQUIRED: "Evidence required",
  HUMAN_REVIEW_REQUIRED: "Human review required",
  NOT_APPLICABLE: "Not applicable",
  PASS: "Passed defined check",
  FAIL: "Failed defined check",
  INCONCLUSIVE: "Inconclusive",
};

export const READINESS_RESULT_LABELS: Record<string, string> = {
  observed: "Observed",
  configured_not_observed: "Configured, not observed",
  passed_by_defined_check: "Passed by defined check",
  failed_by_defined_check: "Failed by defined check",
  unknown: "Unknown",
  conflicting: "Conflicting",
  unsupported: "Unsupported",
  collection_failed: "Collection failed",
  accepted: "Accepted",
  remediation_required: "Remediation required",
  not_applicable: "Not applicable",
  needs_more_data: "Needs more data",
  risk_accepted: "Risk accepted",
  superseded: "Superseded",
};

const LIMITATIONS: Record<string, string> = {
  synthetic_reference: "Synthetic reference data. A live customer environment has not been validated.",
  not_packet_delivery: "A candidate path is not packet delivery.",
  not_compromise: "This is not a recorded compromise.",
  not_control_effectiveness: "Configuration is not observed control effectiveness.",
  absence_is_not_safety: "Absence of a record is not proof of safety.",
  not_a_compliance_result: "This is not a compliance result.",
  not_compliance: "This is not a compliance result.",
  not_effective_reachability: "Observed reachability is not established.",
  snapshot_not_current: "The snapshot is not the current snapshot.",
  control_not_mapped: "No control record names this service.",
  not_exploitability: "This is not an exploitability result.",
  not_threat_relevance: "This is not a threat-relevance verdict.",
  not_evaluated: "This was not evaluated.",
  owner_not_assigned: "Owner not assigned.",
  depends_on: "Depends on",
  service_membership: "Service membership",
  path_node: "Path member",
  healthy: "Healthy",
  disabled: "Disabled",
  running: "Running",
  rate_limited: "Rate limited",
  failed: "Failed",
  due: "Due",
  degraded: "Degraded",
  fixture_only: "Validated with reference data",
  fresh: "Fresh",
  current: "Current",
  untested: "Not tested",
  withdrawn: "Withdrawn",
};

export function presentedValue(value: string): string {
  if (value in TRUTH) return TRUTH[value as TruthKey].label;
  if (MATCH_STATE[value]) return MATCH_STATE[value].label;
  if (SOURCE_LABELS[value]) return SOURCE_LABELS[value];
  if (ASSURANCE_LABELS[value]) return ASSURANCE_LABELS[value];
  if (READINESS_RESULT_LABELS[value]) return READINESS_RESULT_LABELS[value];
  if (LIMITATIONS[value]) return LIMITATIONS[value];
  const published = Object.values(MATCH_STATE).find((item) => item.label === value);
  if (published) return published.label;
  if (/reference|synthetic|fixture|gap-/.test(value)) return "Synthetic reference evidence";
  if (/^[A-Z][A-Z0-9_]*$/.test(value)) return "Unknown state";
  if (/[A-Z\s]/.test(value)) return value;
  return "Unknown state";
}

export function maturityStatement(value: string): string {
  const known = truthFor(value);
  if (!known) return "Unknown state";
  return `${known.label}. ${known.description}`;
}

export const MATCH_STATE: Record<string, { label: string; description: string }> = {
  confirmed_identifier_match: {
    label: "Identifier match",
    description: "The CVE and product identifiers are equal. This is not proof of compromise or that the advisory applies beyond the identifier.",
  },
  version_supported_candidate: {
    label: "Version-supported candidate",
    description: "The recorded version sits inside a complete advisory range. This is a candidate, not a confirmed incident.",
  },
  possible_match: {
    label: "Possible match",
    description: "The product matches and version evidence is incomplete, or only an explicit cloud service and scope match.",
  },
  unknown: { label: "Unknown", description: "The version or range cannot be ordered with the current comparator." },
  conflicting: { label: "Conflicting", description: "Sources disagree about the version relation." },
  not_applicable_by_evidence: {
    label: "Not applicable by evidence",
    description: "The recorded version is outside a complete advisory range. This is not a claim that no risk exists.",
  },
};

export const JOURNEYS = [
  { key: "customer-ordering", title: "Customer ordering", purpose: "Order-taking service and the assets that membership records attach to it." },
  { key: "privileged-administration", title: "Privileged administration", purpose: "Administration path and the assets explicitly attached to it." },
  { key: "remote-access", title: "Remote access and site connectivity", purpose: "Remote access service and the network assets explicitly attached to it." },
] as const;

const FORBIDDEN = ["vulnerable", "compromised", "compliant", "reachable", "safe", "secure"];

export function displayText(value: unknown, max = 180): string {
  const text = String(value ?? "").replace(/[<>]/g, "").replace(/\s+/g, " ").trim();
  return text.slice(0, max);
}

export function matchLabel(state: string): { label: string; description: string } {
  if (MATCH_STATE[state]) return MATCH_STATE[state];
  const published = Object.values(MATCH_STATE).find((item) => item.label === state);
  return published ?? { label: "Unknown state", description: "The stored value is not in the presentation vocabulary." };
}

export function truthFor(value: string): { label: string; description: string } | null {
  if (value in TRUTH) {
    return TRUTH[value as TruthKey];
  }
  return null;
}

export function vocabularyAvoidsForbiddenClaims(): boolean {
  const text = JSON.stringify({ TRUTH, MATCH_STATE, JOURNEYS }).toLowerCase();
  return FORBIDDEN.every((word) => !new RegExp(`\\b${word}\\b`).test(text));
}
