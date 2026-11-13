export type MeterSegment = {
  key: string;
  value: number;
  tone: "ok" | "gap" | "review" | "muted";
};

export function percent(part: number, whole: number): number {
  if (whole <= 0) {
    return 0;
  }
  return Math.round((part / whole) * 100);
}

export function Meter({
  segments,
  label,
}: {
  segments: MeterSegment[];
  label: string;
}) {
  const total = segments.reduce((sum, item) => sum + item.value, 0);
  if (total <= 0) {
    return (
      <div className="meter meter-empty" role="img" aria-label={`${label}: no data yet`}>
        <span className="meter-seg meter-muted" style={{ width: "100%" }} />
      </div>
    );
  }
  return (
    <div className="meter" role="img" aria-label={label}>
      {segments.map((item) => (
        <span
          key={item.key}
          className={`meter-seg meter-${item.tone}`}
          style={{ width: `${(item.value / total) * 100}%` }}
          title={`${item.key}: ${item.value}`}
        />
      ))}
    </div>
  );
}
