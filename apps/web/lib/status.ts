export const ASSURANCE_STATUSES = [
  "VALIDATED",
  "PARTIALLY_VALIDATED",
  "GAP_DETECTED",
  "EVIDENCE_REQUIRED",
  "HUMAN_REVIEW_REQUIRED",
  "NOT_APPLICABLE",
] as const;

export type Tone = "ok" | "gap" | "review" | "neutral" | "fail" | "pass";

export function assuranceTone(status: string): Tone {
  if (status === "VALIDATED") {
    return "ok";
  }
  if (status === "GAP_DETECTED") {
    return "gap";
  }
  if (status === "EVIDENCE_REQUIRED" || status === "HUMAN_REVIEW_REQUIRED" || status === "PARTIALLY_VALIDATED") {
    return "review";
  }
  return "neutral";
}

export function verdictTone(verdict: string): Tone {
  if (verdict === "PASS") {
    return "pass";
  }
  if (verdict === "FAIL") {
    return "fail";
  }
  return "review";
}

export function severityTone(severity: string): Tone {
  if (severity === "high" || severity === "critical") {
    return "fail";
  }
  if (severity === "medium") {
    return "review";
  }
  return "neutral";
}

export function findingStatusTone(status: string): Tone {
  if (status === "resolved") {
    return "ok";
  }
  if (status === "remediated") {
    return "review";
  }
  return "gap";
}

export function freshnessTone(status: string): Tone {
  if (status === "FRESH") {
    return "ok";
  }
  if (status === "STALE") {
    return "review";
  }
  return "neutral";
}
