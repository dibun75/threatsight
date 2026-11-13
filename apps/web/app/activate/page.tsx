"use client";

import { useState, type FormEvent } from "react";

import { api } from "@/lib/api";

export default function ActivatePage() {
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    const token = window.location.hash.replace(/^#/, "");
    try {
      await api("/api/v1/auth/local/activate", { method: "POST", body: JSON.stringify({ token, password }) });
      setMessage("Password saved. You can sign in.");
    } catch {
      setMessage("This link is not valid.");
    }
  }
  return (
    <article className="stack">
      <p className="kicker">ThreatSight</p>
      <h1>Choose a password</h1>
      <form onSubmit={submit}>
        <label htmlFor="password">Password</label>
        <input id="password" type="password" autoComplete="new-password" required minLength={15} maxLength={128} value={password} onChange={(event) => setPassword(event.target.value)} />
        <button className="btn" type="submit">Save password</button>
      </form>
      {message ? <p role="status">{message}</p> : null}
    </article>
  );
}
