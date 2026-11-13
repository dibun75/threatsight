import Link from "next/link";

export const LIFECYCLE = [
  { href: "/requirements", label: "Requirement" },
  { href: "/controls", label: "Control" },
  { href: "/evidence", label: "Evidence" },
  { href: "/assurance", label: "Validation test" },
  { href: "/assurance", label: "Observed impact" },
  { href: "/findings", label: "Verdict" },
  { href: "/assurance", label: "Remediation" },
  { href: "/assurance", label: "Retest" },
] as const;

export function Lifecycle({ compact = false }: { compact?: boolean }) {
  return (
    <ol className={compact ? "lifecycle lifecycle-compact" : "lifecycle"} aria-label="Assurance lifecycle">
      {LIFECYCLE.map((step, index) => (
        <li key={`${step.label}-${index}`}>
          {index > 0 ? (
            <span className="lifecycle-arrow" aria-hidden="true">
              ↓
            </span>
          ) : null}
          <Link href={step.href}>{step.label}</Link>
        </li>
      ))}
    </ol>
  );
}
