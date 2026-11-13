export function SourceTime({ value }: { value: string | null | undefined }) {
  if (!value) return null;
  const parsed = new Date(value);
  const compact = Number.isNaN(parsed.getTime())
    ? value
    : new Intl.DateTimeFormat("en-GB", {
        day: "numeric",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        timeZone: "UTC",
        hourCycle: "h23",
      }).format(parsed);
  return (
    <time className="source-time" dateTime={value} aria-label={`Source updated ${value}`}>
      {compact} UTC
    </time>
  );
}
