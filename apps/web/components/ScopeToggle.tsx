"use client";

import type { RecordScope } from "@/lib/scope";

export function ScopeToggle({
  value,
  onChange,
}: {
  value: RecordScope;
  onChange: (next: RecordScope) => void;
}) {
  return (
    <label className="scope-toggle">
      View
      <select value={value} onChange={(event) => onChange(event.target.value as RecordScope)}>
        <option value="showcase">Showcase (default)</option>
        <option value="all">All records</option>
      </select>
    </label>
  );
}
