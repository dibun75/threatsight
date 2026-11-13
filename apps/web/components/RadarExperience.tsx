"use client";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";

import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";

type Workspace = { key: string; subject: string; role: string };
type Profile = {
  workspace: string;
  countries: string[];
  sectors: string[];
  vendors: string[];
  products: string[];
  technologies: string[];
  critical_services: string[];
  minimum_relevance: number;
};
type Source = {
  key: string;
  provider: string;
  authority: string;
  locator: string;
  sync_mode: string;
  jurisdiction: string | null;
  license_url: string | null;
  storage_policy: string;
  attribution: string;
  last_synced_at: string | null;
  last_status: string;
  last_error: string | null;
  consecutive_failures: number;
};
type Filters = {
  country: string;
  geography: string;
  sector: string;
  vendor: string;
  product: string;
  technology: string;
  event_type: string;
  source: string;
  exploitation_status: string;
  relevance: string;
  minimum_relevance: string;
  sort: string;
  direction: string;
  page: number;
  limit: number;
};
type SavedView = { id: string; name: string; filters: Partial<Filters> };
type Resource = { type: string; id: string; label: string; boundary: string };
type RadarEvent = {
  id: string;
  event_type: string;
  title: string;
  summary: string;
  canonical_url: string;
  published_at: string | null;
  confidence: number;
  cves: string[];
  exploitation_status: string;
  geography: Record<string, string[]>;
  source: Source;
  relevance: { score: number; level: string; reasons: string[] };
  clusters: Array<{
    id: string;
    relationship_type: string;
    title: string;
    factors: string[];
    algorithm_version: string;
  }>;
  triage: {
    status: string;
    priority: string;
    owner: string | null;
    due_at: string | null;
    rationale: string;
  } | null;
  readiness_links: Array<{
    id: string;
    target_type: string;
    target_id: string;
    reason: string;
    limitations: string[];
  }>;
  provenance: Record<string, unknown>;
  limitations: string[];
  exposure_confirmed: boolean;
};
type EventResponse = {
  workspace: string;
  minimum_relevance: number;
  page: number;
  limit: number;
  total: number;
  count: number;
  items: RadarEvent[];
  limitations: string[];
};

const DEFAULT_FILTERS: Filters = {
  country: "",
  geography: "any",
  sector: "",
  vendor: "",
  product: "",
  technology: "",
  event_type: "",
  source: "",
  exploitation_status: "",
  relevance: "",
  minimum_relevance: "0",
  sort: "published_at",
  direction: "desc",
  page: 1,
  limit: 25,
};
const TONES: Record<string, "gap" | "review" | "neutral" | "ok"> = {
  critical: "gap",
  high: "gap",
  medium: "review",
  low: "neutral",
  none: "neutral",
};

function date(value: string | null): string {
  return value
    ? new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value))
    : "Not reported";
}
function list(value: string): string[] {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}
function query(filters: Filters): string {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== "") params.set(key, String(value));
  });
  return params.toString();
}

export function RadarExperience() {
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [sources, setSources] = useState<Source[]>([]);
  const [events, setEvents] = useState<EventResponse | null>(null);
  const [views, setViews] = useState<SavedView[]>([]);
  const [resources, setResources] = useState<Resource[]>([]);
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [mode, setMode] = useState<"timeline" | "list">("timeline");
  const [viewName, setViewName] = useState("");
  const [editingProfile, setEditingProfile] = useState(false);
  const [profileDraft, setProfileDraft] = useState({
    countries: "", sectors: "", vendors: "", products: "", technologies: "",
  });
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const writable = workspace ? ["operator", "reviewer", "admin"].includes(workspace.role) : false;

  async function loadEvents(next: Filters) {
    setEvents(await api<EventResponse>(`/api/v1/radar/events?${query(next)}`));
  }
  async function load() {
    const [nextWorkspace, nextProfile, nextSources, nextViews, nextResources] = await Promise.all([
      api<Workspace>("/api/v1/radar/workspace"),
      api<Profile>("/api/v1/radar/profile"),
      api<Source[]>("/api/v1/radar/sources"),
      api<SavedView[]>("/api/v1/radar/saved-views"),
      api<Resource[]>("/api/v1/radar/resources"),
    ]);
    const nextFilters = { ...DEFAULT_FILTERS, minimum_relevance: String(nextProfile.minimum_relevance) };
    setWorkspace(nextWorkspace);
    setProfile(nextProfile);
    setSources(nextSources);
    setViews(nextViews);
    setResources(nextResources);
    setFilters(nextFilters);
    setProfileDraft({
      countries: nextProfile.countries.join(", "),
      sectors: nextProfile.sectors.join(", "),
      vendors: nextProfile.vendors.join(", "),
      products: nextProfile.products.join(", "),
      technologies: nextProfile.technologies.join(", "),
    });
    await loadEvents(nextFilters);
  }
  useEffect(() => {
    load().catch((reason: Error) => setError(reason.message));
  }, []);

  async function applyFilters(event?: FormEvent) {
    event?.preventDefault();
    setError(null);
    const next = { ...filters, page: 1 };
    setFilters(next);
    try {
      await loadEvents(next);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Radar query failed");
    }
  }
  async function changePage(page: number) {
    const next = { ...filters, page };
    setFilters(next);
    await loadEvents(next);
  }
  async function saveView() {
    if (!viewName.trim()) return;
    setBusy("view");
    try {
      await api<SavedView>("/api/v1/radar/saved-views", {
        method: "POST",
        body: JSON.stringify({
          name: viewName.trim(),
          filters: Object.fromEntries(
            Object.entries(filters).filter(([, value]) => value !== ""),
          ),
        }),
      });
      setViewName("");
      setViews(await api<SavedView[]>("/api/v1/radar/saved-views"));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Saved view failed");
    } finally {
      setBusy(null);
    }
  }
  async function deleteView(id: string) {
    setBusy(id);
    try {
      await api(`/api/v1/radar/saved-views/${id}`, { method: "DELETE" });
      setViews((current) => current.filter((item) => item.id !== id));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Delete failed");
    } finally {
      setBusy(null);
    }
  }
  async function saveProfile() {
    if (!profile) return;
    setBusy("profile");
    try {
      const updated = await api<Profile>("/api/v1/radar/profile", {
        method: "PUT",
        body: JSON.stringify({
          ...profile,
          countries: list(profileDraft.countries).map((item) => item.toUpperCase()),
          sectors: list(profileDraft.sectors),
          vendors: list(profileDraft.vendors),
          products: list(profileDraft.products),
          technologies: list(profileDraft.technologies),
          minimum_relevance: Number(filters.minimum_relevance),
        }),
      });
      setProfile(updated);
      setEditingProfile(false);
      await loadEvents(filters);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Profile update failed");
    } finally {
      setBusy(null);
    }
  }
  async function saveTriage(event: RadarEvent, form: HTMLFormElement) {
    const data = new FormData(form);
    setBusy(`triage-${event.id}`);
    try {
      await api(`/api/v1/radar/triage/event/${event.id}`, {
        method: "PUT",
        body: JSON.stringify({
          status: data.get("status"),
          priority: data.get("priority"),
          owner: data.get("owner") || null,
          due_at: data.get("due_at") ? `${data.get("due_at")}T23:59:59Z` : null,
          rationale: data.get("rationale"),
        }),
      });
      await loadEvents(filters);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Triage update failed");
    } finally {
      setBusy(null);
    }
  }
  async function addLink(event: RadarEvent, form: HTMLFormElement) {
    const data = new FormData(form);
    const selected = resources.find((item) => `${item.type}:${item.id}` === data.get("resource"));
    if (!selected) return;
    setBusy(`link-${event.id}`);
    try {
      await api(`/api/v1/radar/links/event/${event.id}`, {
        method: "POST",
        body: JSON.stringify({
          target_type: selected.type,
          target_id: selected.id,
          reason: data.get("reason"),
          provenance: "Manual analyst linkage in ThreatSight Radar",
          limitations: ["Analyst context only; this link does not prove exposure, effectiveness, incident status, or compliance."],
        }),
      });
      form.reset();
      await loadEvents(filters);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Readiness link failed");
    } finally {
      setBusy(null);
    }
  }
  async function syncSource(key: string) {
    setBusy(key);
    try {
      await api(`/api/v1/radar/sources/${key}/sync`, { method: "POST", body: "{}" });
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Source synchronization failed");
    } finally {
      setBusy(null);
    }
  }

  const partialSources = sources.filter((item) => item.last_status === "failed");
  const elevated = useMemo(
    () => events?.items.filter((item) => ["critical", "high"].includes(item.relevance.level)).length ?? 0,
    [events],
  );

  if (!workspace || !profile || !events) {
    return error
      ? <div role="alert"><ErrorBanner message={error} /><p>Access may be unauthorized or the Radar service may be unavailable.</p></div>
      : <LoadingState label="Correlating authoritative intelligence…" />;
  }

  return (
    <div className="stack">
      <PageHeader
        kicker="Nordic threat & readiness radar"
        title="What changed, why it matters, and who owns the next step."
        lede="Authority reporting is correlated with your workspace profile. It remains informational until asset exposure and control evidence are verified."
      />
      <ErrorBanner message={error} />
      {partialSources.length ? (
        <div className="radar-partial" role="status">
          Partial-source state: {partialSources.map((item) => item.provider).join(", ")} failed its latest synchronization.
          Other source results remain available.
        </div>
      ) : null}

      <section className="radar-summary" aria-label="Radar summary">
        <div className="metric"><b>{events.total}</b><span>events match this view</span></div>
        <div className="metric"><b>{elevated}</b><span>high or critical on this page</span></div>
        <div className="metric"><b>{sources.length - partialSources.length}/{sources.length}</b><span>sources without current failure</span></div>
        <div className="metric"><b>{workspace.key}</b><span>{workspace.role} workspace role</span></div>
      </section>

      <section className="radar-panel">
        <div className="radar-panel-head">
          <div><p className="kicker">Organization lens</p><h2>Explainable relevance profile</h2></div>
          {writable ? <button className="btn secondary" onClick={() => setEditingProfile(!editingProfile)}>{editingProfile ? "Close" : "Edit profile"}</button> : <StatusPill value="read only" tone="neutral" />}
        </div>
        {editingProfile ? (
          <div className="radar-profile-form">
            {Object.entries(profileDraft).map(([field, value]) => (
              <label key={field}>{field.replace("_", " ")}<input value={value} onChange={(event) => setProfileDraft({ ...profileDraft, [field]: event.target.value })} /></label>
            ))}
            <button className="btn" disabled={busy === "profile"} onClick={() => void saveProfile()}>Save and recalculate</button>
          </div>
        ) : (
          <div className="radar-lens">
            <span><b>Countries</b>{profile.countries.join(", ") || "Not set"}</span>
            <span><b>Sectors</b>{profile.sectors.join(", ") || "Not set"}</span>
            <span><b>Vendors / products</b>{[...profile.vendors, ...profile.products].join(", ") || "Not set"}</span>
            <span><b>Technologies</b>{profile.technologies.join(", ") || "Not set"}</span>
          </div>
        )}
      </section>

      <section>
        <div className="radar-panel-head"><div><p className="kicker">Source register</p><h2>Health, provenance, and storage boundary</h2></div></div>
        <div className="source-grid">
          {sources.map((item) => (
            <article className="source-card" key={item.key}>
              <div className="source-title"><div><b>{item.provider}</b><span>{item.authority}</span></div><StatusPill value={item.last_status} tone={item.last_status === "ok" ? "ok" : item.last_status === "failed" ? "gap" : "neutral"} /></div>
              <p>{item.jurisdiction || "Cross-jurisdiction"} authority · {item.sync_mode} · {item.storage_policy.replaceAll("_", " ")}</p>
              <p>Last attempt: {date(item.last_synced_at)}</p>
              <p className="muted">{item.attribution}</p>
              <p><a href={item.license_url || item.locator} target="_blank" rel="noreferrer">Terms and canonical source</a></p>
              {item.last_error ? <p className="error">{item.last_error}</p> : null}
              {writable && item.sync_mode === "automatic" ? <button className="btn secondary" disabled={busy !== null} onClick={() => void syncSource(item.key)}>{busy === item.key ? "Synchronizing…" : "Synchronize"}</button> : null}
              {item.sync_mode === "manual" ? <p className="muted">Metadata-only import boundary; no scraping.</p> : null}
            </article>
          ))}
        </div>
      </section>

      <section>
        <div className="radar-panel-head">
          <div><p className="kicker">Workspace views</p><h2>Filter and retain an investigation lens</h2></div>
          <div className="radar-mode" role="group" aria-label="Display mode">
            <button className="btn secondary" aria-pressed={mode === "timeline"} onClick={() => setMode("timeline")}>Timeline</button>
            <button className="btn secondary" aria-pressed={mode === "list"} onClick={() => setMode("list")}>List</button>
          </div>
        </div>
        <form className="radar-filters" onSubmit={(event) => void applyFilters(event)}>
          <label>Country<input maxLength={2} placeholder="NO" value={filters.country} onChange={(event) => setFilters({ ...filters, country: event.target.value.toUpperCase() })} /></label>
          <label>Geographic meaning<select value={filters.geography} onChange={(event) => setFilters({ ...filters, geography: event.target.value })}>{["any", "authority", "target", "victim", "infrastructure", "prevalence"].map((item) => <option key={item}>{item}</option>)}</select></label>
          <label>Sector<input value={filters.sector} onChange={(event) => setFilters({ ...filters, sector: event.target.value })} /></label>
          <label>Vendor<input value={filters.vendor} onChange={(event) => setFilters({ ...filters, vendor: event.target.value })} /></label>
          <label>Product<input value={filters.product} onChange={(event) => setFilters({ ...filters, product: event.target.value })} /></label>
          <label>Technology<input value={filters.technology} onChange={(event) => setFilters({ ...filters, technology: event.target.value })} /></label>
          <label>Event type<select value={filters.event_type} onChange={(event) => setFilters({ ...filters, event_type: event.target.value })}><option value="">All</option>{["advisory", "vulnerability", "campaign", "incident_report", "national_risk_level_change"].map((item) => <option key={item} value={item}>{item.replaceAll("_", " ")}</option>)}</select></label>
          <label>Source<select value={filters.source} onChange={(event) => setFilters({ ...filters, source: event.target.value })}><option value="">All</option>{sources.filter((item) => item.key !== "first-epss").map((item) => <option key={item.key} value={item.key}>{item.provider}</option>)}</select></label>
          <label>Relevance<select value={filters.relevance} onChange={(event) => setFilters({ ...filters, relevance: event.target.value })}><option value="">All</option>{["critical", "high", "medium", "low", "none"].map((item) => <option key={item}>{item}</option>)}</select></label>
          <label>Exploitation<select value={filters.exploitation_status} onChange={(event) => setFilters({ ...filters, exploitation_status: event.target.value })}><option value="">All</option>{["known_exploited", "proof_of_concept", "suspected", "not_observed", "unknown"].map((item) => <option key={item} value={item}>{item.replaceAll("_", " ")}</option>)}</select></label>
          <label>Minimum score<input type="number" min="0" max="100" value={filters.minimum_relevance} onChange={(event) => setFilters({ ...filters, minimum_relevance: event.target.value })} /></label>
          <label>Sort<select value={filters.sort} onChange={(event) => setFilters({ ...filters, sort: event.target.value })}><option value="published_at">Published</option><option value="updated_at">Updated</option><option value="relevance">Relevance</option></select></label>
          <button className="btn" type="submit">Apply filters</button>
        </form>
        <div className="saved-view-bar">
          <label>Saved view<select defaultValue="" onChange={(event) => {
            const selected = views.find((item) => item.id === event.target.value);
            if (selected) {
              const next = { ...DEFAULT_FILTERS, ...selected.filters, page: 1 };
              setFilters(next);
              void loadEvents(next);
            }
          }}><option value="">Choose…</option>{views.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
          {writable ? <><label>New view name<input value={viewName} onChange={(event) => setViewName(event.target.value)} /></label><button className="btn secondary" disabled={busy === "view" || !viewName.trim()} onClick={() => void saveView()}>Save current filters</button></> : null}
          {writable && views.length ? <details><summary>Manage views</summary>{views.map((item) => <button key={item.id} className="text-action" disabled={busy === item.id} onClick={() => void deleteView(item.id)}>Delete {item.name}</button>)}</details> : null}
        </div>

        {events.items.length === 0 ? <EmptyState title="No matching events" detail="Change the bounded filters, lower the relevance threshold, or check source health." /> : (
          <div className={`event-list radar-${mode}`}>
            {events.items.map((item) => (
              <article className="event-card" key={item.id}>
                <div className="event-score"><b>{item.relevance.score}</b><StatusPill value={item.relevance.level} tone={TONES[item.relevance.level] || "neutral"} /></div>
                <div className="event-body">
                  <div className="event-meta"><span>{item.source.provider}</span><span>{date(item.published_at)}</span><span>{item.event_type.replaceAll("_", " ")}</span><span>{item.exploitation_status.replaceAll("_", " ")}</span></div>
                  <h3><a href={item.canonical_url} target="_blank" rel="noreferrer">{item.title}</a></h3>
                  <p>{item.summary}</p>
                  <ul className="reason-list">{item.relevance.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                  {item.clusters.length ? <div className="cluster-context"><b>Related reporting</b>{item.clusters.map((cluster) => <p key={cluster.id}>{cluster.relationship_type.replaceAll("_", " ")}: {cluster.title}. {cluster.factors.join("; ")} ({cluster.algorithm_version})</p>)}</div> : <p className="muted">No deterministic duplicate or related-event cluster.</p>}
                  {item.cves[0] ? <p><Link href={`/exposure/matches?cve=${encodeURIComponent(item.cves[0])}`}>Candidate asset matches for {item.cves[0]}</Link>. This advisory is not a customer incident.</p> : <p>No CVE is attached, so there is no candidate-match link.</p>}
                  <details className="event-provenance"><summary>What is known, uncertain, and licensed</summary><dl><div><dt>Authority jurisdiction</dt><dd>{item.geography.authority_jurisdictions?.join(", ") || "Not stated"}</dd></div><div><dt>Targets / victims</dt><dd>{[...(item.geography.target_countries || []), ...(item.geography.victim_countries || [])].join(", ") || "Not asserted"}</dd></div><div><dt>Confidence</dt><dd>{Math.round(item.confidence * 100)}%</dd></div><div><dt>Storage</dt><dd>{item.source.storage_policy.replaceAll("_", " ")}</dd></div><div><dt>Limits</dt><dd>{item.limitations.join(" ") || "See source."}</dd></div><div><dt>Exposure</dt><dd>Not confirmed</dd></div></dl></details>
                  {writable ? (
                  <div className="workflow-grid">
                    <form onSubmit={(event) => { event.preventDefault(); void saveTriage(item, event.currentTarget); }}>
                      <h4>Triage and assignment</h4>
                      <label>Status<select name="status" defaultValue={item.triage?.status || "new"}>{["new", "reviewing", "action_required", "monitoring", "resolved", "dismissed"].map((value) => <option key={value}>{value}</option>)}</select></label>
                      <label>Priority<select name="priority" defaultValue={item.triage?.priority || "unassigned"}>{["unassigned", "low", "medium", "high", "urgent"].map((value) => <option key={value}>{value}</option>)}</select></label>
                      <label>Owner<input name="owner" defaultValue={item.triage?.owner || ""} /></label>
                      <label>Due date<input name="due_at" type="date" defaultValue={item.triage?.due_at?.slice(0, 10) || ""} /></label>
                      <label>Rationale<textarea name="rationale" required defaultValue={item.triage?.rationale || ""} /></label>
                      <button className="btn secondary" disabled={busy === `triage-${item.id}`}>Save triage</button>
                    </form>
                    <form onSubmit={(event) => { event.preventDefault(); void addLink(item, event.currentTarget); }}>
                      <h4>Manual readiness context</h4>
                      <label>Bound resource<select name="resource" required defaultValue=""><option value="" disabled>Choose…</option>{resources.map((resource) => <option key={`${resource.type}:${resource.id}`} value={`${resource.type}:${resource.id}`}>{resource.type}: {resource.label}</option>)}</select></label>
                      <label>Reason<textarea name="reason" required /></label>
                      <button className="btn secondary" disabled={busy === `link-${item.id}`}>Add analyst link</button>
                      <p className="muted">Links are analyst context only and never create PASS, FAIL, exposure, incident, or compliance claims.</p>
                      {item.readiness_links.map((link) => <p key={link.id}><b>{link.target_type}</b> — {link.reason}</p>)}
                    </form>
                  </div>
                  ) : (
                    <p>Recorded triage and links stay visible. This demonstration cannot change them.</p>
                  )}
                  {!writable && item.readiness_links.map((link) => <p key={link.id}><b>{link.target_type}</b> — {link.reason}</p>)}
                </div>
              </article>
            ))}
          </div>
        )}
        <nav className="radar-pagination" aria-label="Radar pages">
          <button className="btn secondary" disabled={filters.page <= 1} onClick={() => void changePage(filters.page - 1)}>Previous</button>
          <span>Page {filters.page} · {events.total} total</span>
          <button className="btn secondary" disabled={filters.page * filters.limit >= events.total} onClick={() => void changePage(filters.page + 1)}>Next</button>
        </nav>
        <div className="radar-limitations">{events.limitations.map((item) => <p key={item}>{item}</p>)}</div>
      </section>
    </div>
  );
}
