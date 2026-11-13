"use client";

import { useEffect, useState, type FormEvent } from "react";

import { ApiError, api } from "@/lib/api";

type Account = { email: string; enabled: boolean; role: string };

export default function AccessPage() {
  const [items, setItems] = useState<Account[]>([]);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const [notice, setNotice] = useState("");
  const [link, setLink] = useState("");

  function load() {
    api<{ items: Account[] }>("/api/v1/auth/local/accounts")
      .then((body) => setItems(body.items))
      .catch((error: unknown) => setNotice(error instanceof ApiError ? error.message : "Accounts could not be loaded."));
  }

  useEffect(load, []);

  async function invite(event: FormEvent) {
    event.preventDefault();
    setLink("");
    const body = await api<{ token: string }>("/api/v1/auth/local/accounts", {
      method: "POST",
      body: JSON.stringify({ email, role }),
    });
    setLink(`${window.location.origin}/activate#${body.token}`);
    setEmail("");
  }

  return (
    <article className="stack">
      <h1>Access</h1>
      <p>Invite-only. Open registration is not enabled.</p>
      {notice ? <p role="alert">{notice}</p> : null}
      <ul>
        {items.map((item) => (
          <li key={item.email}>
            {item.email} · {item.role} · {item.enabled ? "enabled" : "disabled"}
            <button type="button" onClick={() => api("/api/v1/auth/local/accounts/change", { method: "POST", body: JSON.stringify({ email: item.email, enabled: !item.enabled }) }).then(load)}>
              {item.enabled ? "Disable" : "Enable"}
            </button>
          </li>
        ))}
      </ul>
      <form onSubmit={invite}>
        <label htmlFor="invite-email">Email</label>
        <input id="invite-email" type="email" required value={email} onChange={(event) => setEmail(event.target.value)} />
        <label htmlFor="invite-role">Role</label>
        <select id="invite-role" value={role} onChange={(event) => setRole(event.target.value)}>
          <option value="viewer">Viewer</option>
          <option value="auditor">Auditor</option>
          <option value="operator">Operator</option>
          <option value="workspace-admin">Workspace administrator</option>
        </select>
        <button className="btn" type="submit">Create invitation</button>
      </form>
      {link ? (
        <p>
          <label htmlFor="one-time">One-time link</label>
          <input id="one-time" readOnly value={link} onFocus={(event) => event.currentTarget.select()} />
        </p>
      ) : null}
    </article>
  );
}
