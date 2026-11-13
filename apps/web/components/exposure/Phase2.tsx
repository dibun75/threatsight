"use client";

import Link from "next/link";
import { FormEvent, Fragment, useEffect, useState } from "react";

import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { TruthMark } from "@/components/TruthMark";
import { ApiError, api, errorKind } from "@/lib/api";
import { EXPOSURE_NAV } from "@/lib/navigation";
import { formatWhen } from "@/lib/time";
import { JOURNEYS, displayText, matchLabel } from "@/lib/vocabulary";

type Snapshot = { id: string; completed_at: string | null; node_count: number; edge_count: number; limitations: string[] };
type Run = { id: string; completed_at: string | null; ruleset_version: string; limitations: string[]; match_count?: number; result_count?: number; status: string };
type Node = {
  id: string;
  node_type: string;
  source_key: string;
  label: string;
  maturity: string;
  evidence_mode: string;
  connector_key: string;
  freshness: string;
  collected_at: string | null;
  limitations: string[];
  attributes: Record<string, unknown>;
};
type Member = { member_node_id: string; role: string; evidence_mode: string; maturity: string };
type Result = {
  id: string;
  category: string;
  state: string;
  rule_id: string;
  explanation: string;
  evidence_modes: string[];
  freshness: string;
  maturity: string;
  limitations: string[];
  missing_facts: string[];
  node_keys: string[];
  edge_keys: string[];
  service_key: string;
};
type Match = {
  id: string;
  state: string;
  rule_id: string;
  cve: string;
  asset_key: string;
  source_count: number;
  sources: string[];
  services: Array<{ source_key: string; evidence_mode?: string }>;
  freshness: string;
  maturity: string;
  explanation: string;
  limitations: string[];
  missing_facts: string[];
  version_evidence: Record<string, unknown>;
  identifier_evidence: Record<string, unknown>;
  epss_score: number | null;
  epss_date: string | null;
  exploitation_status: string;
  review_state: string;
  geography: Record<string, string[]>;
};
type Review = { id: string; decision: string; reason: string; actor: string; expires_at: string | null };
type Connector = { id: string; connector_key: string; name: string; maturity: string; health_state: string; mode: string; last_health_at: string | null };
type Session = { role: string };

const HIDDEN = /secret|password|token|credential|locator|payload|key/i;

function visibleAttributes(attributes: Record<string, unknown>) {
  return Object.entries(attributes).filter(([key, value]) => !HIDDEN.test(key) && typeof value !== "object").slice(0, 8);
}

export function ExposureNav({ current }: { current: string }) {
  return (
    <nav className="subnav" aria-label="Exposure">
      {EXPOSURE_NAV.map((item) => (
        <Link key={item.href} href={item.href} aria-current={item.href === current ? "page" : undefined}>{item.label}</Link>
      ))}
    </nav>
  );
}

function Missing({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty" role="status">
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

function useLoad<T>(path: string) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    api<T>(path, { signal: controller.signal })
      .then((body) => setData(body))
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason);
      })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, [path]);
  return { data, error, loading };
}

function explain(error: unknown): string {
  const kind = errorKind(error);
  if (kind === "missing") return "No completed record exists for this workspace. An empty result is not a safety conclusion.";
  if (kind === "forbidden") return "This role cannot view or change that record.";
  if (kind === "unauthorized") return "Sign in is required.";
  if (kind === "invalid") return "The request was rejected. No change was made.";
  if (kind === "conflict") return "Another run is current, or the record changed.";
  return "The service is unavailable. Counts below are not shown.";
}

export function ExposureHome() {
  const snapshot = useLoad<Snapshot>("/api/v1/graph/snapshots/current");
  const analysis = useLoad<Run>("/api/v1/analysis/current");
  const correlation = useLoad<Run>("/api/v1/correlation/current");
  const services = useLoad<Node[]>("/api/v1/graph/services?limit=20");
  useEffect(() => { document.title = "Exposure — ThreatSight"; }, []);
  return (
    <>
      <PageHeader kicker="Exposure" title="What may apply, and what is still unknown" lede="A candidate is not an incident. No completed collection is not a statement that nothing applies." crumbs={[{ href: "/", label: "Overview" }, { label: "Exposure" }]} />
      <ExposureNav current="/exposure" />
      {snapshot.loading ? <LoadingState label="Loading the current snapshot" /> : null}
      {snapshot.error ? <Missing title="No completed snapshot" detail={explain(snapshot.error)} /> : null}
      {snapshot.data ? <p>Current snapshot completed {formatWhen(snapshot.data.completed_at)}. {snapshot.data.node_count} nodes and {snapshot.data.edge_count} relationships. Limitations: {snapshot.data.limitations.join(", ") || "none recorded"}.</p> : null}
      <section>
        <h2>Analysis and matches</h2>
        <p>{analysis.data ? `${analysis.data.result_count ?? 0} path results, ruleset ${analysis.data.ruleset_version}, ${formatWhen(analysis.data.completed_at)}.` : explain(analysis.error)}</p>
        <p>{correlation.data ? `${correlation.data.match_count ?? 0} candidate matches, ruleset ${correlation.data.ruleset_version}, ${formatWhen(correlation.data.completed_at)}.` : explain(correlation.error)}</p>
        {correlation.data?.limitations.includes("replayed_snapshot") ? <TruthMark value="replayed_snapshot" /> : null}
      </section>
      <section>
        <h2>Reference journeys</h2>
        <ul className="record-list">
          {JOURNEYS.map((journey) => {
            const found = services.data?.find((item) => item.source_key.includes(journey.key));
            return (
              <li key={journey.key} className="record">
                <h3>{journey.title}</h3>
                <p>{journey.purpose}</p>
                <TruthMark value="synthetic" /> <TruthMark value="fixture_tested" />
                {found ? <p><Link href={`/exposure/services/${found.id}`}>{displayText(found.label)}</Link></p> : <p>This journey is not in the current snapshot.</p>}
              </li>
            );
          })}
        </ul>
      </section>
      <p><Link href="/assurance">Assurance context</Link>. Opening it does not change a control verdict.</p>
    </>
  );
}

export function ServiceList() {
  const services = useLoad<Node[]>("/api/v1/graph/services?limit=50");
  useEffect(() => { document.title = "Business services — ThreatSight"; }, []);
  return (
    <>
      <PageHeader kicker="Exposure" title="Business services" lede="Membership means a service depends on a recorded asset. It does not mean the service was compromised." crumbs={[{ href: "/exposure", label: "Exposure" }, { label: "Business services" }]} />
      <ExposureNav current="/exposure/services" />
      {services.loading ? <LoadingState label="Loading services" /> : null}
      {services.error ? <Missing title="Services unavailable" detail={explain(services.error)} /> : null}
      <ul className="record-list">
        {services.data?.map((item) => (
          <li key={item.id} className="record">
            <h2><Link href={`/exposure/services/${item.id}`}>{displayText(item.label || item.source_key)}</Link></h2>
            <p>{displayText(item.source_key, 120)}</p>
            <TruthMark value={item.maturity} /> <TruthMark value={item.evidence_mode} /> <TruthMark value={item.freshness} />
          </li>
        ))}
      </ul>
      {services.data && services.data.length === 0 ? <Missing title="No services in this snapshot" detail="The snapshot completed and returned no business services. That is not a safety conclusion." /> : null}
    </>
  );
}

export function ServiceDetail({ id }: { id: string }) {
  const service = useLoad<{ service: Node; members: Member[]; limitations: string[] }>(`/api/v1/graph/services/${id}/members?limit=50`);
  const matches = useLoad<Match[]>("/api/v1/correlation/services?limit=50");
  const paths = useLoad<Result[]>(`/api/v1/analysis/results?limit=20&service_id=${id}`);
  useEffect(() => { document.title = "Service — ThreatSight"; }, []);
  const related = matches.data?.filter((item) => service.data && item.services.some((entry) => entry.source_key === service.data?.service.source_key)) ?? [];
  return (
    <>
      <PageHeader kicker="Business service" title={displayText(service.data?.service.label || "Service")} lede="Synthetic and reference-data labels apply when the API reports that maturity." crumbs={[{ href: "/exposure/services", label: "Business services" }, { label: "Service" }]} />
      <ExposureNav current="/exposure/services" />
      {service.loading ? <LoadingState label="Loading the service" /> : null}
      {service.error ? <Missing title="Service not available" detail={explain(service.error)} /> : null}
      {service.data ? (
        <>
          <p><TruthMark value={service.data.service.maturity} /> <TruthMark value={service.data.service.freshness} /></p>
          <p>{displayText(service.data.service.source_key, 160)}</p>
          <h2>Members</h2>
          {service.data.members.length === 0 ? <Missing title="No members" detail="No explicit membership was stored. That does not mean the service has no dependencies." /> : (
            <ul className="record-list">
              {service.data.members.map((member) => (
                <li key={member.member_node_id} className="record">
                  <Link href={`/exposure/assets/${member.member_node_id}`}>{member.role}</Link>
                  <TruthMark value={member.evidence_mode} /> <TruthMark value={member.maturity} />
                </li>
              ))}
            </ul>
          )}
          <h2>Candidate matches</h2>
          {related.length === 0 ? <p>No candidate match names this service in the current run.</p> : related.map((item) => <p key={item.id}><Link href={`/exposure/matches/${item.id}`}>{item.cve}</Link> · {matchLabel(item.state).label}</p>)}
          <h2>Path candidates</h2>
          {paths.data?.length ? paths.data.map((item) => <p key={item.id}><Link href={`/exposure/paths/${item.id}`}>{item.rule_id}</Link> · {item.state}</p>) : <p>{paths.error ? explain(paths.error) : "No path result is stored for this service."}</p>}
          <p><Link href="/controls">Controls that may require verification</Link>. This page does not change their status.</p>
        </>
      ) : null}
    </>
  );
}

export function AssetList() {
  const [nodeType, setNodeType] = useState("");
  const assets = useLoad<Node[]>(`/api/v1/graph/nodes?limit=50${nodeType ? `&node_type=${encodeURIComponent(nodeType)}` : ""}`);
  useEffect(() => { document.title = "Assets — ThreatSight"; }, []);
  return (
    <>
      <PageHeader kicker="Exposure" title="Assets" lede="This page shows at most 50 nodes from the current snapshot. It does not load the whole graph." crumbs={[{ href: "/exposure", label: "Exposure" }, { label: "Assets" }]} />
      <ExposureNav current="/exposure/assets" />
      <form>
        <label>Source type
          <select value={nodeType} onChange={(event) => setNodeType(event.target.value)}>
            <option value="">Any loaded type</option>
            {["device", "business_service", "software_version", "cloud_resource", "identity", "network", "public_address"].map((item) => <option key={item} value={item}>{item.replaceAll("_", " ")}</option>)}
          </select>
        </label>
      </form>
      {assets.loading ? <LoadingState label="Loading assets" /> : null}
      {assets.error ? <Missing title="Assets unavailable" detail={explain(assets.error)} /> : null}
      <ul className="record-list">
        {assets.data?.map((item) => (
          <li key={item.id} className="record">
            <h2><Link href={`/exposure/assets/${item.id}`}>{displayText(item.label || item.source_key)}</Link></h2>
            <p>{item.node_type} · {item.connector_key || "no connector"}</p>
            <TruthMark value={item.maturity} /> <TruthMark value={item.freshness} />
          </li>
        ))}
      </ul>
    </>
  );
}

export function AssetDetail({ id }: { id: string }) {
  const neighborhood = useLoad<{ node: Node; neighbors: Node[]; edges: Array<{ edge_type: string; evidence_mode: string; freshness: string }>; limitations: string[] }>(`/api/v1/graph/nodes/${id}`);
  useEffect(() => { document.title = "Asset — ThreatSight"; }, []);
  const node = neighborhood.data?.node;
  return (
    <>
      <PageHeader kicker="Asset" title={displayText(node?.label || "Asset")} lede="Attributes that look like secrets are not shown." crumbs={[{ href: "/exposure/assets", label: "Assets" }, { label: "Asset" }]} />
      <ExposureNav current="/exposure/assets" />
      {neighborhood.loading ? <LoadingState label="Loading the asset" /> : null}
      {neighborhood.error ? <Missing title="Asset not available" detail={explain(neighborhood.error)} /> : null}
      {node ? (
        <>
          <p>{node.node_type} · collected {formatWhen(node.collected_at)}</p>
          <p><TruthMark value={node.maturity} /> <TruthMark value={node.evidence_mode} /> <TruthMark value={node.freshness} /></p>
          <dl className="facts">
            <dt>Source key</dt><dd>{displayText(node.source_key, 180)}</dd>
            <dt>Connector</dt><dd>{displayText(node.connector_key || "Not recorded")}</dd>
            {visibleAttributes(node.attributes).map(([key, value]) => (
              <Fragment key={key}><dt>{displayText(key, 40)}</dt><dd>{displayText(value)}</dd></Fragment>
            ))}
          </dl>
          <h2>Relationships</h2>
          <ul className="step-list">
            {neighborhood.data?.edges.map((edge, index) => (
              <li key={`${edge.edge_type}-${index}`} className="step">{edge.edge_type} · <TruthMark value={edge.evidence_mode} /> <TruthMark value={edge.freshness} /></li>
            ))}
          </ul>
          {neighborhood.data?.limitations.includes("neighborhood_truncated") ? <TruthMark value="partial" /> : null}
          <p>Neighbor labels: {neighborhood.data?.neighbors.map((item) => displayText(item.label || item.source_key, 60)).join(", ") || "none on this page"}.</p>
        </>
      ) : null}
    </>
  );
}

export function PathList() {
  const results = useLoad<Result[]>("/api/v1/analysis/results?limit=50");
  useEffect(() => { document.title = "Paths — ThreatSight"; }, []);
  return (
    <>
      <PageHeader kicker="Exposure" title="Candidate paths" lede="A supported candidate is configuration or membership evidence. It is not observed packet flow." crumbs={[{ href: "/exposure", label: "Exposure" }, { label: "Paths" }]} />
      <ExposureNav current="/exposure/paths" />
      {results.loading ? <LoadingState label="Loading path results" /> : null}
      {results.error ? <Missing title="No path analysis" detail={explain(results.error)} /> : null}
      <table>
        <caption>Path results in the current completed analysis</caption>
        <thead><tr><th>Rule</th><th>State</th><th>Service</th><th>Freshness</th></tr></thead>
        <tbody>
          {results.data?.map((item) => (
            <tr key={item.id}>
              <td><Link href={`/exposure/paths/${item.id}`}>{item.rule_id}</Link></td>
              <td>{item.state.replaceAll("_", " ")}</td>
              <td>{displayText(item.service_key, 80) || "Not tied to one service"}</td>
              <td><TruthMark value={item.freshness} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export function PathDetail({ id }: { id: string }) {
  const result = useLoad<Result>(`/api/v1/analysis/results/${id}`);
  const chain = useLoad<{ service_id: string | null; steps: Array<{ from: string; relationship: string; to: string; evidence_state: string; source: string; freshness: string; limitation: string }> }>(`/api/v1/investigations/paths/${id}`);
  useEffect(() => { document.title = "Path — ThreatSight"; }, []);
  return (
    <>
      <PageHeader kicker="Path" title={result.data?.rule_id || "Path"} lede="Steps are source keys in the order the analysis stored them. Direction is the stored relationship, not a packet trace." crumbs={[{ href: "/exposure/paths", label: "Paths" }, { label: "Path" }]} />
      <ExposureNav current="/exposure/paths" />
      {result.loading ? <LoadingState label="Loading the path" /> : null}
      {result.error ? <Missing title="Path not available" detail={explain(result.error)} /> : null}
      {chain.data?.service_id ? <p><Link href={`/services/${chain.data.service_id}`}>Back to service</Link></p> : <p>No stored service key names this path.</p>}
      {result.data ? (
        <>
          <p>{result.data.state.replaceAll("_", " ")}. {displayText(result.data.explanation, 400)}</p>
          <p>{result.data.evidence_modes.map((mode) => <TruthMark key={mode} value={mode} />)}</p>
          <ol className="step-list">
            {result.data.node_keys.map((key, index) => <li key={`${key}-${index}`} className="step"><h3>Step {index + 1}</h3><p>{displayText(key, 180)}</p></li>)}
          </ol>
          <table>
            <caption>Same path as a table</caption>
            <thead><tr><th>Step</th><th>Record</th><th>Relationship</th></tr></thead>
            <tbody>
              {result.data.node_keys.map((key, index) => (
                <tr key={`row-${key}-${index}`}><td>{index + 1}</td><td>{displayText(key, 120)}</td><td>{displayText(result.data?.edge_keys[index] || "End", 80)}</td></tr>
              ))}
            </tbody>
          </table>
          {chain.data ? (
            <table>
              <caption>Ordered relationship steps. This table is the accessible source of truth.</caption>
              <thead><tr><th scope="col">From</th><th scope="col">Relationship</th><th scope="col">To</th><th scope="col">Evidence</th><th scope="col">Source</th><th scope="col">Freshness</th></tr></thead>
              <tbody>
                {chain.data.steps.map((step, index) => (
                  <tr key={`${step.relationship}-${index}`}><th scope="row">{step.from}</th><td>{step.relationship}</td><td>{step.to}</td><td>{step.evidence_state}. {step.limitation}</td><td>{step.source}</td><td>{step.freshness}</td></tr>
                ))}
              </tbody>
            </table>
          ) : null}
          {result.data.missing_facts.length ? <p>Missing: {result.data.missing_facts.map((item) => displayText(item, 80)).join(", ")}</p> : null}
          {result.data.limitations.some((item) => item.includes("limit") || item.includes("traversal")) ? <TruthMark value="partial" /> : null}
        </>
      ) : null}
    </>
  );
}

export function MatchList({ cve }: { cve?: string }) {
  const path = `/api/v1/correlation/matches?limit=50${cve ? `&cve=${encodeURIComponent(cve)}` : ""}`;
  const matches = useLoad<Match[]>(path);
  useEffect(() => { document.title = "Threat matches — ThreatSight"; }, []);
  return (
    <>
      <PageHeader kicker="Exposure" title="Threat matches" lede="Identifier equality is not an incident. KEV and EPSS stay separate. Country fields are source roles, not attacker origin." crumbs={[{ href: "/exposure", label: "Exposure" }, { label: "Threat matches" }]} />
      <ExposureNav current="/exposure/matches" />
      {cve ? <p>Filtered to {displayText(cve, 20)}. <Link href="/exposure/matches">Clear filter</Link></p> : null}
      {matches.loading ? <LoadingState label="Loading matches" /> : null}
      {matches.error ? <Missing title="No match run" detail={explain(matches.error)} /> : null}
      <ul className="record-list">
        {matches.data?.map((item) => {
          const state = matchLabel(item.state);
          return (
            <li key={item.id} className="record">
              <h2><Link href={`/exposure/matches/${item.id}`}>{item.cve}</Link></h2>
              <p title={state.description}>{state.label}</p>
              <p>{displayText(item.asset_key, 120)}</p>
              <p>KEV status {item.exploitation_status}. EPSS {item.epss_score ?? "not recorded"} {item.epss_date ? `on ${item.epss_date}` : ""}.</p>
              <TruthMark value={item.freshness} /> <span>Review {item.review_state.replaceAll("_", " ")}</span>
            </li>
          );
        })}
      </ul>
      {matches.data && matches.data.length === 0 ? <Missing title="No matches in this filter" detail="The completed run stored no row for this filter. A missing row is not a safety conclusion." /> : null}
    </>
  );
}

export function MatchDetail({ id }: { id: string }) {
  const match = useLoad<Match>(`/api/v1/correlation/matches/${id}`);
  const reviews = useLoad<Review[]>(`/api/v1/correlation/matches/${id}/reviews?limit=20`);
  const session = useLoad<Session>("/api/v1/radar/workspace");
  const [message, setMessage] = useState("");
  const [done, setDone] = useState("");
  useEffect(() => { document.title = "Match — ThreatSight"; }, []);
  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const decision = String(form.get("decision") || "");
    const reason = String(form.get("reason") || "");
    const expires = String(form.get("expires_at") || "");
    setMessage("");
    try {
      await api(`/api/v1/correlation/matches/${id}/reviews`, {
        method: "POST",
        body: JSON.stringify({ decision, reason, expires_at: decision === "suppressed_until" ? new Date(expires).toISOString() : null }),
      });
      setDone("Review recorded. The underlying match was not deleted.");
      window.location.reload();
    } catch (error) {
      setMessage(explain(error));
    }
  }
  const state = match.data ? matchLabel(match.data.state) : null;
  const canReview = session.data?.role === "workspace-admin" || session.data?.role === "platform-admin";
  return (
    <>
      <PageHeader kicker="Threat match" title={match.data?.cve || "Match"} lede={state?.description} crumbs={[{ href: "/exposure/matches", label: "Threat matches" }, { label: "Match" }]} />
      <ExposureNav current="/exposure/matches" />
      {match.loading ? <LoadingState label="Loading the match" /> : null}
      {match.error ? <Missing title="Match not available" detail={explain(match.error)} /> : null}
      {match.data && state ? (
        <>
          <p title={state.description}><strong>{state.label}</strong> · {match.data.rule_id}</p>
          <p>{displayText(match.data.explanation, 400)}</p>
          <dl className="facts">
            <dt>Asset</dt><dd>{displayText(match.data.asset_key, 180)}</dd>
            <dt>Services</dt><dd>{match.data.services.map((item) => displayText(item.source_key, 80)).join(", ") || "No explicit service propagation"}</dd>
            <dt>Sources</dt><dd>{match.data.source_count} contributing events. {match.data.sources.map((item) => displayText(item, 40)).join(", ")}</dd>
            <dt>KEV</dt><dd>{match.data.exploitation_status}. This does not mean this workspace was attacked.</dd>
            <dt>EPSS</dt><dd>{match.data.epss_score ?? "Not recorded"} {match.data.epss_date ? `dated ${match.data.epss_date}` : ""}. This is not impact.</dd>
            <dt>Review</dt><dd>{match.data.review_state.replaceAll("_", " ")}{match.data.limitations.includes("review_evidence_changed") ? ". Evidence changed, so the displayed review returned to unreviewed." : ""}</dd>
            <dt>Geography</dt><dd>Authority {match.data.geography.authority_jurisdictions?.join(", ") || "not stated"}. Target {match.data.geography.target_countries?.join(", ") || "not stated"}.</dd>
          </dl>
          <p>Version evidence: {displayText(JSON.stringify(match.data.version_evidence), 240)}</p>
          <p>Identifier evidence: {displayText(JSON.stringify(match.data.identifier_evidence), 240)}</p>
          {match.data.limitations.map((item) => truthForLimit(item))}
          <h2>Review history</h2>
          <ul>
            {reviews.data?.map((item) => <li key={item.id}>{item.decision.replaceAll("_", " ")} by {displayText(item.actor, 40)}. {displayText(item.reason, 180)} {item.expires_at ? `Expires ${formatWhen(item.expires_at)}.` : ""}</li>)}
          </ul>
          {canReview ? (
            <form className="form" onSubmit={onSubmit}>
              <label>Decision
                <select name="decision" defaultValue="not_applicable">
                  <option value="accepted_relevant">Accepted as relevant</option>
                  <option value="not_applicable">Not applicable</option>
                  <option value="needs_more_data">Needs more data</option>
                  <option value="suppressed_until">Suppressed until</option>
                </select>
              </label>
              <label>Reason<input name="reason" minLength={8} maxLength={400} required /></label>
              <label>Expiry for suppression<input name="expires_at" type="datetime-local" /></label>
              <button className="btn" type="submit">Record review</button>
            </form>
          ) : <p>This role can read the match. Recording a review requires a workspace administrator.</p>}
          {message ? <ErrorBanner message={message} /> : null}
          {done ? <p role="status">{done}</p> : null}
          <p><Link href="/controls">Related control context</Link></p>
        </>
      ) : null}
    </>
  );
}

function truthForLimit(item: string) {
  if (item === "stale_input" || item === "stale_source") return <TruthMark key={item} value="stale" />;
  if (item.includes("conflict")) return <TruthMark key={item} value="conflicting" />;
  if (item.includes("limit") || item === "partial") return <TruthMark key={item} value="partial" />;
  return null;
}

export function ConnectorHealth() {
  const connectors = useLoad<Connector[]>("/api/v1/connectors/instances");
  const runners = useLoad<Array<{ id: string; status: string; name?: string }>>("/api/v1/connectors/runners");
  useEffect(() => { document.title = "Connectors — ThreatSight"; }, []);
  const named = [
    ["azure.resource_graph", "Microsoft Azure"],
    ["entra.identity", "Microsoft Entra"],
    ["meraki.dashboard", "Cisco Meraki"],
    ["junos.device", "Juniper Junos"],
  ] as const;
  return (
    <>
      <PageHeader kicker="Exposure" title="Connectors and data health" lede="A fixture contract is not a live connection. No instance means live collection was not validated." crumbs={[{ href: "/exposure", label: "Exposure" }, { label: "Connectors" }]} />
      <ExposureNav current="/exposure/connectors" />
      {connectors.loading ? <LoadingState label="Loading connectors" /> : null}
      <ul className="record-list">
        {named.map(([key, label]) => {
          const found = connectors.data?.find((item) => item.connector_key === key);
          return (
            <li key={key} className="record">
              <h2>{label}</h2>
              {found ? (
                <>
                  <p>{found.maturity === "live_verified" ? "Live connection recorded." : "Synthetic reference contract passed. Live connection not validated."}</p>
                  <p>Health {found.health_state}. Mode {found.mode}. Last health check {formatWhen(found.last_health_at)}.</p>
                  <TruthMark value={found.maturity} />
                </>
              ) : <p>No instance configured. Live connection not validated.</p>}
            </li>
          );
        })}
      </ul>
      <h2>Runners</h2>
      {runners.error ? <p>{explain(runners.error)}</p> : null}
      {runners.data && runners.data.length === 0 ? <Missing title="No runner registered" detail="Runner disconnected is not the same as a passed fixture." /> : null}
      <ul>{runners.data?.map((item) => <li key={item.id}>{displayText(item.name || "Runner")} · {item.status}</li>)}</ul>
    </>
  );
}
