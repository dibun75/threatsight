import { csrfHeaders } from "./api";

export async function revokeBrowserSession(): Promise<"revoked" | "unchanged"> {
  const response = await fetch("/api/v1/auth/logout", {
    method: "POST",
    credentials: "same-origin",
    redirect: "manual",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...csrfHeaders(),
    },
  });
  if (response.status !== 204 && response.status !== 200) return "unchanged";
  const check = await fetch("/api/v1/auth/session", { method: "GET", cache: "no-store", credentials: "same-origin" });
  return check.status === 401 ? "revoked" : "unchanged";
}
