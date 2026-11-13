const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1"]);

export function browserFacingOrigin(input: {
  nextOrigin: string;
  nextHost: string;
  host: string | null;
  forwardedHost: string | null;
  forwardedProto: string | null;
  protocol: string;
}): string {
  const forwarded = (input.forwardedHost || "").split(",")[0].trim();
  const host = (input.host || "").trim();
  const candidate = forwarded || host;
  const protocol = (input.forwardedProto || input.protocol || "").split(",")[0].trim().replace(/:$/, "");
  const name = candidate.replace(/:\d+$/, "").replace(/^\[|\]$/g, "").toLowerCase();
  if (
    (protocol === "http" || protocol === "https")
    && candidate
    && !/[\s@\\/?#]/.test(candidate)
    && (candidate.toLowerCase() === input.nextHost.toLowerCase() || LOOPBACK.has(name))
  ) {
    return `${protocol}://${candidate}`;
  }
  return input.nextOrigin;
}
