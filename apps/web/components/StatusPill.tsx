import { type Tone } from "@/lib/status";

export function StatusPill({
  value,
  tone,
}: {
  value: string;
  tone?: Tone;
}) {
  return <span className={`pill${tone ? ` pill-${tone}` : ""}`}>{value}</span>;
}
