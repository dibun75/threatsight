/** A read-only API token (tsk_...) is the only Authorization header a browser or tool may send through the proxy. */
export function apiTokenFrom(source: Headers): string {
  const header = source.get("authorization") ?? "";
  if (!header.toLowerCase().startsWith("bearer ")) return "";
  const token = header.slice(7).trim();
  return /^tsk_[A-Za-z0-9_-]{16,200}$/.test(token) ? token : "";
}

export function upstreamHeaders(source: Headers): Headers {
  const headers = new Headers();
  const contentType = source.get("content-type");
  const accept = source.get("accept");
  const requestId = source.get("x-request-id");
  const cookie = source.get("cookie");
  const origin = source.get("origin");
  const csrf = source.get("x-csrf-token");
  if (contentType) headers.set("content-type", contentType);
  if (accept) headers.set("accept", accept);
  if (requestId && /^[A-Za-z0-9-]{1,80}$/.test(requestId)) headers.set("x-request-id", requestId);
  if (cookie) headers.set("cookie", cookie);
  if (origin) headers.set("origin", origin);
  if (csrf) headers.set("x-csrf-token", csrf);
  const token = apiTokenFrom(source);
  if (token) headers.set("authorization", `Bearer ${token}`);
  return headers;
}

export function browserResponseHeaders(status: number, upstream: Headers): Headers {
  const outgoing = new Headers();
  const responseType = upstream.get("content-type");
  const disposition = upstream.get("content-disposition");
  const responseRequestId = upstream.get("x-request-id");
  const location = upstream.get("location");
  const setCookies = typeof upstream.getSetCookie === "function" ? upstream.getSetCookie() : [];
  if (responseType) outgoing.set("content-type", responseType);
  if (disposition) outgoing.set("content-disposition", disposition);
  if (responseRequestId) outgoing.set("x-request-id", responseRequestId);
  if (location && [301, 302, 303, 307, 308].includes(status)) outgoing.set("location", location);
  for (const cookie of setCookies) outgoing.append("set-cookie", cookie);
  if (setCookies.length === 0) {
    const setCookie = upstream.get("set-cookie");
    if (setCookie) outgoing.append("set-cookie", setCookie);
  }
  outgoing.set("cache-control", "no-store");
  return outgoing;
}
