"use client";

import { useEffect, useState, type FormEvent } from "react";

import { ApiError, api } from "@/lib/api";

type Token = { id: string; name: string; prefix: string; created_at: string | null; last_used_at: string | null; revoked_at: string | null };
type Destination = { id: string; kind: string; label: string; target: string; has_secret: boolean; enabled: boolean };
type Delivery = { time: string; event: string; destination: string; kind: string; ok: boolean; error: string | null };
type Overview = { destinations: Destination[]; deliveries: Delivery[]; fires_on: string[] };

const KINDS = [
  { value: "webhook", label: "Webhook (signed)" },
  { value: "slack", label: "Slack" },
  { value: "teams", label: "Microsoft Teams" },
  { value: "syslog", label: "SIEM (syslog, CEF)" },
];

function message(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

export default function IntegrationsPage() {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [notice, setNotice] = useState("");
  const [fresh, setFresh] = useState("");
  const [tokenName, setTokenName] = useState("");
  const [kind, setKind] = useState("webhook");
  const [label, setLabel] = useState("");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("514");
  const [protocol, setProtocol] = useState("udp");

  function load() {
    api<{ items: Token[] }>("/api/v1/auth/tokens")
      .then((body) => setTokens(body.items))
      .catch((error: unknown) => setNotice(message(error, "API tokens could not be loaded.")));
    api<Overview>("/api/v1/integrations/alerts")
      .then(setOverview)
      .catch((error: unknown) => setNotice(message(error, "Alert destinations could not be loaded.")));
  }

  useEffect(load, []);

  async function run(action: () => Promise<unknown>, failure: string) {
    setNotice("");
    try {
      await action();
      load();
    } catch (error) {
      setNotice(message(error, failure));
    }
  }

  async function issue(event: FormEvent) {
    event.preventDefault();
    setFresh("");
    await run(async () => {
      const body = await api<{ token: string }>("/api/v1/auth/tokens", { method: "POST", body: JSON.stringify({ name: tokenName }) });
      setFresh(body.token);
      setTokenName("");
    }, "The token could not be created.");
  }

  async function addDestination(event: FormEvent) {
    event.preventDefault();
    const body = kind === "syslog"
      ? { kind, label, host, port: Number(port), protocol }
      : { kind, label, url, secret: kind === "webhook" ? secret : undefined };
    await run(async () => {
      await api("/api/v1/integrations/alerts/destinations", { method: "POST", body: JSON.stringify(body) });
      setLabel("");
      setUrl("");
      setSecret("");
      setHost("");
    }, "The destination could not be added.");
  }

  async function test(id: string) {
    await run(async () => {
      const result = await api<{ ok: boolean; error: string | null }>(`/api/v1/integrations/alerts/destinations/${id}/test`, { method: "POST" });
      setNotice(result.ok ? "Test alert delivered." : `Test alert failed: ${result.error ?? "no detail"}`);
    }, "The test could not be sent.");
  }

  return (
    <article className="stack">
      <h1>Integrations</h1>
      <p>Read-only API tokens for exports and BI tools, and alerts when a readiness check returns its fail condition. An alert is not a statement of compromise.</p>
      {notice ? <p role="alert">{notice}</p> : null}

      <section aria-labelledby="tokens-title" className="stack">
        <h2 id="tokens-title">API tokens</h2>
        <p>
          A token can only read: GET requests to the exports and other read routes, with <code>Authorization: Bearer tsk_…</code>.
          It cannot write or open owner settings. The token is shown once.
        </p>
        {fresh ? <p role="status">New token (copy it now): <code>{fresh}</code></p> : null}
        <ul>
          {tokens.map((token) => (
            <li key={token.id}>
              {token.name} · <code>{token.prefix}</code> · {token.revoked_at ? "revoked" : token.last_used_at ? `last used ${token.last_used_at}` : "never used"}
              {token.revoked_at ? null : (
                <button type="button" onClick={() => run(() => api(`/api/v1/auth/tokens/${token.id}`, { method: "DELETE" }), "The token could not be revoked.")}>
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
        <form onSubmit={issue}>
          <label htmlFor="token-name">Token name</label>
          <input id="token-name" required maxLength={120} value={tokenName} onChange={(event) => setTokenName(event.target.value)} />
          <button className="btn" type="submit">Create token</button>
        </form>
      </section>

      <section aria-labelledby="alerts-title" className="stack">
        <h2 id="alerts-title">Alert destinations</h2>
        <ul>
          {(overview?.destinations ?? []).map((item) => (
            <li key={item.id}>
              {item.label} · {item.kind} · <code>{item.target}</code>{item.has_secret ? " · signed" : ""} · {item.enabled ? "on" : "off"}
              <button type="button" onClick={() => test(item.id)}>Send test</button>
              <button type="button" onClick={() => run(() => api(`/api/v1/integrations/alerts/destinations/${item.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !item.enabled }) }), "The change could not be saved.")}>
                {item.enabled ? "Turn off" : "Turn on"}
              </button>
              <button type="button" onClick={() => run(() => api(`/api/v1/integrations/alerts/destinations/${item.id}`, { method: "DELETE" }), "The destination could not be removed.")}>
                Remove
              </button>
            </li>
          ))}
        </ul>
        <form onSubmit={addDestination}>
          <label htmlFor="dest-kind">Type</label>
          <select id="dest-kind" value={kind} onChange={(event) => setKind(event.target.value)}>
            {KINDS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
          <label htmlFor="dest-label">Name</label>
          <input id="dest-label" required maxLength={80} value={label} onChange={(event) => setLabel(event.target.value)} />
          {kind === "syslog" ? (
            <>
              <label htmlFor="dest-host">Host</label>
              <input id="dest-host" required value={host} onChange={(event) => setHost(event.target.value)} />
              <label htmlFor="dest-port">Port</label>
              <input id="dest-port" type="number" min={1} max={65535} value={port} onChange={(event) => setPort(event.target.value)} />
              <label htmlFor="dest-protocol">Protocol</label>
              <select id="dest-protocol" value={protocol} onChange={(event) => setProtocol(event.target.value)}>
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
              </select>
            </>
          ) : (
            <>
              <label htmlFor="dest-url">Webhook URL</label>
              <input id="dest-url" type="url" required value={url} onChange={(event) => setUrl(event.target.value)} />
              {kind === "webhook" ? (
                <>
                  <label htmlFor="dest-secret">Signing secret (optional)</label>
                  <input id="dest-secret" type="password" autoComplete="off" maxLength={200} value={secret} onChange={(event) => setSecret(event.target.value)} />
                </>
              ) : null}
            </>
          )}
          <button className="btn" type="submit">Add destination</button>
        </form>
        <h3>Recent deliveries</h3>
        {overview && overview.deliveries.length > 0 ? (
          <ul>
            {overview.deliveries.map((item, index) => (
              <li key={`${item.time}-${index}`}>{item.time} · {item.destination} · {item.event} · {item.ok ? "delivered" : `failed: ${item.error ?? "no detail"}`}</li>
            ))}
          </ul>
        ) : (
          <p>No alerts sent yet.</p>
        )}
      </section>
    </article>
  );
}
