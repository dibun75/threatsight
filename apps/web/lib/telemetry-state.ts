export type PresentationState =
  | "loading"
  | "current"
  | "stale"
  | "failed_with_last_known_good"
  | "disabled"
  | "failed_without_snapshot";

export type TelemetryInput = {
  state?: string | null;
  hasSnapshot?: boolean;
} | null;

const HAS_SNAPSHOT = new Set(["current", "stale", "failed_using_last_known_good", "no_data_returned"]);

export function presentTelemetry(input: TelemetryInput, pending = false): PresentationState {
  if (pending || input == null) return "loading";
  const state = input.state ?? "";
  const hasSnapshot = input.hasSnapshot ?? HAS_SNAPSHOT.has(state);
  if (state === "current" || state === "no_data_returned") return "current";
  if (state === "stale") return "stale";
  if (state === "failed_using_last_known_good") return "failed_with_last_known_good";
  if (state === "disabled" || state === "externally_gated") return "disabled";
  if (state === "failed_no_snapshot") return "failed_without_snapshot";
  if (state === "collecting") return hasSnapshot ? "current" : "loading";
  return hasSnapshot ? "failed_with_last_known_good" : "failed_without_snapshot";
}

export function telemetryHeadline(state: PresentationState): string {
  if (state === "loading") return "";
  if (state === "current") return "Live global observations";
  if (state === "stale") return "Last observation is stale";
  if (state === "failed_with_last_known_good") return "Showing the last saved measurement. The latest refresh failed.";
  if (state === "disabled") return "Collection is not enabled.";
  return "No validated snapshot is available.";
}

export function primaryAction(text: string | null | undefined): string {
  if (!text) return "";
  if (/validate the installed/i.test(text) && /owner/i.test(text)) return "Validate the installed version and assign an owner.";
  return text;
}

const FORBIDDEN_WHILE_LOADING = [
  "not connected",
  "no data",
  "no decision",
  "units are not stored",
  "collection failed",
  "no prioritized service",
  "not recorded",
];

export function loadingCopyIsNeutral(copy: string): boolean {
  const lower = copy.toLowerCase();
  return FORBIDDEN_WHILE_LOADING.every((phrase) => !lower.includes(phrase));
}
