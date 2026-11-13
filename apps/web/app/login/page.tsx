"use client";

import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState, type FormEvent } from "react";

import { ApiError, api } from "@/lib/api";
import { revokeBrowserSession } from "@/lib/logout";
import { dataContextLabel, identityLines, roleLabel, safeContinuePath, type SessionContext } from "@/lib/session";

type AuthStatus = { mode: string; oidc_configured: boolean; detail: string };

function Login() {
  const params = useSearchParams();
  const expired = params.get("reason") === "expired";
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [error, setError] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [current, setCurrent] = useState<SessionContext | null>(null);
  const [sessionCheck, setSessionCheck] = useState<"pending" | "present" | "absent">("pending");
  const [logoutState, setLogoutState] = useState<"idle" | "working" | "failed">("idle");
  useEffect(() => {
    api<AuthStatus>("/api/v1/auth/status").then(setStatus).catch(() => setError("Sign-in status could not be loaded."));
    api<SessionContext>("/api/v1/auth/session")
      .then((body) => {
        setCurrent(body);
        setSessionCheck("present");
      })
      .catch(() => {
        setCurrent(null);
        setSessionCheck("absent");
      });
  }, []);
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
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setError("");
    try {
      await api("/api/v1/auth/local/login", { method: "POST", body: JSON.stringify({ email, password }) });
      const next = params.get("return_to");
      window.location.assign(next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/login") ? next : "/demo");
    } catch (caught) {
      setError(caught instanceof ApiError ? "Sign-in failed." : "Sign-in failed.");
      setSubmitting(false);
    }
  }
  const identity = current ? identityLines(current.display_name, current.account) : null;
  return (
    <section className="auth-screen">
      <article className="auth-card">
        <p className="auth-cue">Private access</p>
        <h1>{sessionCheck === "present" ? "Already signed in" : "Sign in"}</h1>
        <p className="auth-lead">ThreatSight connects threat change to the decisions your teams must make.</p>
        {expired && sessionCheck !== "present" ? <p role="status">Your session has expired. Sign in again.</p> : null}
        {error ? <p className="auth-error" role="alert">{error}</p> : null}
        {sessionCheck === "pending" && !error ? <p role="status">Checking sign-in.</p> : null}
        {sessionCheck === "present" && current && identity ? (
          <div className="auth-session">
            <p role="status">This browser already has an active session.</p>
            <dl className="auth-facts">
              {identity.name ? <><dt>Name</dt><dd>{identity.name}</dd></> : null}
              <dt>Account</dt><dd>{identity.account}</dd>
              <dt>Role</dt><dd>{roleLabel(current.role)}</dd>
              <dt>Workspace</dt><dd>{current.workspace_name}</dd>
              <dt>Data context</dt><dd>{dataContextLabel(current.data_context)}</dd>
            </dl>
            <div className="auth-actions">
              <a className="btn" href={safeContinuePath(params.get("return_to"))}>Continue to ThreatSight</a>
              <button className="btn secondary" type="button" onClick={() => void logout()} disabled={logoutState === "working"}>
                {logoutState === "working" ? "Signing out" : "Log out"}
              </button>
            </div>
            {logoutState === "failed" ? <p className="auth-error" role="alert">Sign-out did not complete. The session is still active.</p> : null}
          </div>
        ) : null}
        {sessionCheck === "absent" && status?.mode === "local" ? (
          <form className="auth-form" onSubmit={(event) => void submit(event)}>
            <label htmlFor="email">Email</label>
            <input id="email" name="email" type="email" autoComplete="username" required value={email} onChange={(event) => setEmail(event.target.value)} />
            <label htmlFor="password">Password</label>
            <div className="auth-password">
              <input id="password" name="password" type={showPassword ? "text" : "password"} autoComplete="current-password" required minLength={15} maxLength={128} value={password} onChange={(event) => setPassword(event.target.value)} />
              <button type="button" aria-pressed={showPassword} onClick={() => setShowPassword((value) => !value)}>
                {showPassword ? "Hide password" : "Show password"}
              </button>
            </div>
            <button className="btn" type="submit" disabled={submitting} aria-busy={submitting}>
              {submitting ? "Signing in" : "Sign in"}
            </button>
          </form>
        ) : null}
        {status?.oidc_configured && sessionCheck !== "present" ? <p><a className="btn secondary" href="/api/v1/auth/login?return_to=/demo">Sign in with Microsoft</a></p> : null}
        {status && status.mode !== "local" && !status.oidc_configured && sessionCheck !== "present" ? <p role="status">{status.detail}</p> : null}
        <p className="auth-note">Authorized users only.</p>
      </article>
    </section>
  );
}

export default function LoginPage() {
  return <Suspense fallback={<section className="auth-screen"><article className="auth-card"><p role="status">Checking sign-in.</p></article></section>}><Login /></Suspense>;
}
