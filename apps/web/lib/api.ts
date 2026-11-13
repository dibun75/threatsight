export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function errorKind(error: unknown): "unauthorized" | "forbidden" | "missing" | "conflict" | "unavailable" | "invalid" | "aborted" {
  if (error instanceof DOMException && error.name === "AbortError") return "aborted";
  const status = error instanceof ApiError ? error.status : 0;
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "missing";
  if (status === 409) return "conflict";
  if (status === 422 || status === 429) return "invalid";
  return "unavailable";
}

export function csrfHeaders(): Record<string, string> {
  if (typeof document === "undefined") return {};
  const match = document.cookie.match(/(?:^|; )(?:__Host-threatsight_csrf|threatsight_csrf)=([^;]*)/);
  if (!match?.[1]) return {};
  return { "X-CSRF-Token": decodeURIComponent(match[1]) };
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...csrfHeaders(),
      ...(init?.headers ?? {}),
    },
  });
  return readResponse<T>(response);
}

export async function upload<T>(path: string, file: File, fields?: Record<string, string>): Promise<T> {
  const body = new FormData();
  body.append("file", file);
  if (fields) {
    for (const [key, value] of Object.entries(fields)) {
      body.append(key, value);
    }
  }
  const response = await fetch(path, {
    method: "POST",
    body,
    headers: csrfHeaders(),
  });
  return readResponse<T>(response);
}

function safeDetail(status: number, body: string): string {
  const known: Record<number, string> = {
    401: "Sign in is required.",
    403: "This role cannot perform that action.",
    404: "The requested record was not found.",
    409: "The record changed or a run is already in progress.",
    422: "The request was rejected.",
    429: "The request was rate limited.",
  };
  if (known[status]) return known[status];
  if (status >= 500) return "The service is unavailable.";
  try {
    const parsed = JSON.parse(body) as { detail?: unknown };
    if (typeof parsed.detail === "string" && parsed.detail.length < 80 && !parsed.detail.includes("<")) return parsed.detail;
  } catch {
    return "The request could not be completed.";
  }
  return "The request could not be completed.";
}

async function readResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.text();
    throw new ApiError(response.status, safeDetail(response.status, body));
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}
