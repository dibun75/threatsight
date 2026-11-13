export function safeRedirect(
  requestPath: string[],
  location: string,
  authorizationEndpoint: string,
): boolean {
  if (!location || /[\r\n\\]/.test(location)) return false;
  if (requestPath.join("/") === "v1/auth/login") {
    if (!authorizationEndpoint) return false;
    try {
      const target = new URL(location);
      const allowed = new URL(authorizationEndpoint);
      return (
        target.protocol === "https:" &&
        allowed.protocol === "https:" &&
        target.origin === allowed.origin &&
        target.pathname === allowed.pathname &&
        !target.username &&
        !target.password &&
        !target.hash
      );
    } catch {
      return false;
    }
  }
  return location.startsWith("/") && !location.startsWith("//") && !location.includes("://");
}
