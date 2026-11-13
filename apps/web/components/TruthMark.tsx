import { truthFor } from "@/lib/vocabulary";

const CAUTION = new Set(["partial", "stale", "unknown", "conflicting", "unsupported", "inferred", "replayed_snapshot", "fixture_tested", "synthetic", "configured"]);
const VERIFIED = new Set(["live_verified", "observed"]);

export function TruthMark({ value }: { value: string }) {
  const known = truthFor(value);
  const label = known?.label ?? "Unknown state";
  const description = known?.description ?? "The stored value is not in the presentation vocabulary.";
  const tone = VERIFIED.has(value) ? "verified" : value === "conflicting" ? "urgent" : CAUTION.has(value) ? "caution" : "info";
  return (
    <span className="truth" data-tone={tone} title={description}>
      <i aria-hidden="true" />
      <span>{label}</span>
      <span className="sr-only">. {description}</span>
    </span>
  );
}
