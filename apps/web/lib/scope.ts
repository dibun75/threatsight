export type RecordScope = "showcase" | "all";

export function withScope(path: string, scope: RecordScope): string {
  const join = path.includes("?") ? "&" : "?";
  return `${path}${join}scope=${scope}`;
}
