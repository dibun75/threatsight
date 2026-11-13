export type SessionContext = {
  display_name: string;
  account: string;
  role: string;
  workspace_name: string;
  workspace_key: string;
  tenant_name: string;
  data_context: string;
  logout_available: boolean;
};

const ROLE_LABELS: Record<string, string> = {
  viewer: "Viewer",
  auditor: "Auditor",
  operator: "Operator",
  "workspace-admin": "Workspace administrator",
  "platform-admin": "Platform administrator",
};

export function roleLabel(role: string): string {
  return ROLE_LABELS[role] ?? "Signed-in user";
}

export function dataContextLabel(value: string): string {
  if (value === "Synthetic reference" || value === "Operational data") return value;
  return "Reference data";
}

export function identityLines(displayName: string, account: string): { name: string; account: string } {
  const id = account.trim();
  const name = displayName.trim();
  if (!name || name.localeCompare(id, undefined, { sensitivity: "accent" }) === 0) return { name: "", account: id };
  return { name, account: id };
}

export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean).slice(0, 2);
  if (parts.length === 0) return "TS";
  return parts.map((part) => part[0]?.toUpperCase() ?? "").join("") || "TS";
}

export function safeContinuePath(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\") || value.startsWith("/login")) {
    return "/demo";
  }
  return value;
}
