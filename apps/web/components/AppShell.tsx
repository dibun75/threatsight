"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

import { ApiError, api } from "@/lib/api";
import { revokeBrowserSession } from "@/lib/logout";
import { navCurrent } from "@/lib/experience";
import { ADMIN_NAV, PRIMARY_NAV, PUBLIC_NAV, SUPPORT_NAV, type NavItem } from "@/lib/navigation";
import { dataContextLabel, identityLines, initials, roleLabel, type SessionContext } from "@/lib/session";
import { formatWhen } from "@/lib/time";
type Snapshot = { completed_at: string | null; node_count: number; limitations: string[] };

function current(pathname: string, href: string) {
  return navCurrent(pathname, href);
}

function itemCurrent(pathname: string, item: NavItem) {
  return item.matches?.some((href) => current(pathname, href) === "page") ? "page" : current(pathname, item.href);
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [navOpen, setNavOpen] = useState(false);
  const [adminOpen, setAdminOpen] = useState(false);
  const [session, setSession] = useState<SessionContext | null>(null);
  const [sessionState, setSessionState] = useState<"loading" | "ready" | "signed-out" | "anonymous" | "unavailable">("loading");
  const [logoutState, setLogoutState] = useState<"idle" | "working" | "failed">("idle");
  const [freshness, setFreshness] = useState("Checking collection");
  const [apiState, setApiState] = useState("Checking API");
  const [publicDemo, setPublicDemo] = useState(true);

  useEffect(() => {
    setNavOpen(false);
  }, [pathname]);

  useEffect(() => {
    const controller = new AbortController();
    api<{ mode: string }>("/api/v1/auth/status", { signal: controller.signal })
      .then((status) => {
        if (status.mode !== "local" && status.mode !== "oidc") {
          setSession(null);
          setSessionState("anonymous");
          setApiState("API available");
          return;
        }
        return api<SessionContext>("/api/v1/auth/session", { signal: controller.signal }).then((body) => {
          setSession(body);
          setSessionState("ready");
          setApiState("API available");
        });
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setSession(null);
        if (error instanceof ApiError && error.status === 401) {
          setSessionState("signed-out");
          setApiState("Sign in required");
          return;
        }
        setSessionState("unavailable");
        setApiState("API unavailable");
      });
    api<{ public_demo?: boolean }>("/api/v1/ops/status", { signal: controller.signal })
      .then((body) => setPublicDemo(body.public_demo === true))
      .catch(() => setPublicDemo(true));
    api<Snapshot>("/api/v1/graph/snapshots/current", { signal: controller.signal })
      .then((body) => setFreshness(body.completed_at ? `Graph ${formatWhen(body.completed_at)}` : "Graph time not recorded"))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setFreshness(error instanceof ApiError && error.status === 404 ? "No completed exposure snapshot" : "Exposure freshness unavailable");
      });
    const refreshCachedPage = (event: PageTransitionEvent) => {
      if (event.persisted) window.location.reload();
    };
    window.addEventListener("pageshow", refreshCachedPage);
    return () => {
      controller.abort();
      window.removeEventListener("pageshow", refreshCachedPage);
    };
  }, []);

  const gate = pathname === "/login" || pathname === "/activate" || pathname === "/reset";
  const landing = pathname === "/" || gate;
  const navigation = publicDemo ? PUBLIC_NAV : PRIMARY_NAV;
  const adminActive = ADMIN_NAV.some((item) => item.href !== "/threats/catalog" && current(pathname, item.href) === "page");
  async function logout() {
    if (logoutState === "working") return;
    setLogoutState("working");
    const result = await revokeBrowserSession();
    if (result === "revoked") {
      window.location.assign("/login");
      return;
    }
    setLogoutState("failed");
  }

  const restricted = publicDemo && (
    adminActive
    || pathname === "/governance" || pathname.startsWith("/governance/")
    || pathname === "/lab" || pathname.startsWith("/lab/")
    || pathname === "/reports" || pathname.startsWith("/reports/")
  );

  return (
    <div className={landing ? "landing-shell" : `shell${navOpen ? " nav-open" : ""}`}>
      <a className="skip" href="#content">Skip to content</a>
      <p className="reference-banner" role="status">
        Synthetic enterprise · Live public intelligence. No customer systems are connected.
      </p>
      {landing ? (
        <header className="landing-bar">
          <Link href="/">ThreatSight</Link>
          {gate ? null : (
          <nav aria-label="Product">
            <Link href="/demo">Explore the command center</Link>
            <Link href="/tour">See how it works</Link>
          </nav>
          )}
        </header>
      ) : (
      <>
      <button className="nav-toggle" type="button" aria-expanded={navOpen} onClick={() => setNavOpen((value) => !value)}>
        {navOpen ? "Close menu" : "Menu"}
      </button>
      <aside className="rail" data-open={navOpen ? "true" : "false"}>
        <div className="mark">
          <span className="mark-title">ThreatSight</span>
          <span className="mark-kicker">Hybrid security readiness</span>
        </div>
        <section className="workspace-block" aria-label="Workspace">
          <span className="context-label">Workspace</span>
          <span className="workspace-name">{session ? session.workspace_name : sessionState === "loading" ? "Loading workspace" : sessionState === "unavailable" ? "Workspace unavailable" : "Signed out"}</span>
          <span className="context-label">Data context</span>
          <span className="environment-badge">{session ? dataContextLabel(session.data_context) : sessionState === "loading" ? "Checking…" : "Context unavailable"}</span>
        </section>
        <nav className="nav" aria-label="Primary">
          {navigation.map((item) => (
            <Link key={item.href} href={item.href} aria-current={itemCurrent(pathname, item)}>{item.label}</Link>
          ))}
          <details className="nav-group nav-support">
            <summary>Help and briefing</summary>
            {SUPPORT_NAV.map((item) => (
              <Link key={item.href} href={item.href} aria-current={itemCurrent(pathname, item)}>{item.label}</Link>
            ))}
          </details>
          {publicDemo ? null : (
          <div className="nav-group">
            <button className="nav-more" type="button" aria-expanded={adminOpen || adminActive} onClick={() => setAdminOpen((value) => !value)}>
              Administration
            </button>
            {adminOpen || adminActive
              ? ADMIN_NAV.map((item) => (
                  <Link key={item.href} href={item.href} aria-current={current(pathname, item.href)}>{item.label}</Link>
                ))
              : null}
          </div>
          )}
        </nav>
        <div className="rail-foot">
          <section className="account-block" aria-label="Account">
            {sessionState === "ready" && session ? (
              <>
                <span className="avatar" aria-hidden="true">{initials(identityLines(session.display_name, session.account).name || session.account)}</span>
                {identityLines(session.display_name, session.account).name ? <span className="account-name">{identityLines(session.display_name, session.account).name}</span> : null}
                <span className="account-id">{identityLines(session.display_name, session.account).account}</span>
                <span className="account-role">{roleLabel(session.role)}</span>
                {session.logout_available ? (
                  <button className="btn" type="button" onClick={() => void logout()} disabled={logoutState === "working"}>
                    {logoutState === "working" ? "Signing out" : "Log out"}
                  </button>
                ) : null}
                {logoutState === "failed" ? <span role="alert">Sign-out did not complete. The session is still active.</span> : null}
              </>
            ) : (
              <>
                <span>{sessionState === "loading" ? "Checking session" : sessionState === "signed-out" ? "Sign in required" : sessionState === "anonymous" ? "Reference access" : "Session could not be confirmed"}</span>
                {sessionState === "unavailable" || sessionState === "signed-out" ? (
                  <button type="button" onClick={() => window.location.assign("/login")}>Open sign-in</button>
                ) : null}
              </>
            )}
          </section>
          <details>
            <summary>Collection status</summary>
            <span>{freshness}</span>
            <span>{apiState}</span>
          </details>
        </div>
      </aside>
      </>
      )}
      <main className="main" id="content">
        {restricted ? (
          <section className="stack">
            <h1>Not part of this demonstration</h1>
            <p>Administration stays available to an authenticated operator. This public demonstration is read-only and does not show operational configuration.</p>
            <p><Link href="/tour">Return to the guided tour</Link></p>
          </section>
        ) : children}
      </main>
    </div>
  );
}
