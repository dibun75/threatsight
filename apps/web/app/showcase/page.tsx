"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { ConfirmButton } from "@/components/ConfirmButton";
import { EmptyState } from "@/components/EmptyState";
import { ErrorBanner } from "@/components/ErrorBanner";
import { Lifecycle } from "@/components/Lifecycle";
import { LoadingState } from "@/components/LoadingState";
import { PageHeader } from "@/components/PageHeader";
import { StatusPill } from "@/components/StatusPill";
import { api } from "@/lib/api";
import { freshnessTone, verdictTone } from "@/lib/status";

type Step = { id: string; title: string; href: string; why: string; group?: string };
type Story = { id: string; title: string; href: string; body: string };
type Scenario = {
  company: string;
  ai_system: string;
  inventory_name: string;
  purpose: string;
  risk: string;
  control: string;
  control_identifier: string;
  labelled_synthetic: boolean;
  legal_compliance_claim: boolean;
};
type Status = {
  legal_compliance_claim: boolean;
  llm_authors_executive_summary: boolean;
  autonomous_attack: boolean;
  exploitation_engine: boolean;
  unrestricted_crawl: boolean;
  confirm_execution_required_for_auth01: boolean;
  evidence_fresh_days: number;
  walkthrough: Step[];
  guided_story?: Story[];
  scenario?: Scenario;
};
type Bootstrap = {
  legal_compliance_claim: boolean;
  executed_auth01: boolean;
  verdict: string | null;
  walkthrough: Step[];
  guided_story?: Story[];
  assurance: { system_id: string; control_id: string };
};
type Matrix = {
  legal_compliance_claim: boolean;
  items: Array<{
    control: string;
    control_id: string;
    requirement: string | null;
    test: string | null;
    result: string | null;
    evidence: string | null;
    owner: string;
    framework: string | null;
    freshness: string;
  }>;
};

function StepList({ steps }: { steps: Step[] }) {
  return (
    <ol>
      {steps.map((step) => (
        <li key={step.id}>
          <Link href={step.href}>{step.title}</Link>
          <div className="muted">{step.why}</div>
        </li>
      ))}
    </ol>
  );
}

export default function ShowcasePage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [walkthrough, setWalkthrough] = useState<Step[]>([]);
  const [story, setStory] = useState<Story[]>([]);
  const [matrix, setMatrix] = useState<Matrix | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  async function loadStatus() {
    const body = await api<Status>("/api/v1/showcase/status");
    setStatus(body);
    setWalkthrough(body.walkthrough);
    setStory(body.guided_story || []);
  }

  async function loadMatrix() {
    setMatrix(await api<Matrix>("/api/v1/exports/control-matrix.json?scope=showcase"));
  }

  useEffect(() => {
    Promise.all([loadStatus(), loadMatrix()]).catch((err: Error) => setError(err.message));
  }, []);

  async function bootstrap(confirmExecution: boolean) {
    setError(null);
    setBusy(true);
    try {
      const body = await api<Bootstrap>("/api/v1/showcase/demo/bootstrap", {
        method: "POST",
        body: JSON.stringify({ confirm_execution: confirmExecution }),
      });
      setWalkthrough(body.walkthrough);
      if (body.guided_story) {
        setStory(body.guided_story);
      }
      setLoaded(true);
      await loadMatrix();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Showcase load failed");
    } finally {
      setBusy(false);
    }
  }

  async function resetShowcase() {
    setError(null);
    setBusy(true);
    try {
      const body = await api<Bootstrap>("/api/v1/showcase/demo/reset", {
        method: "POST",
        body: JSON.stringify({ reseed: true, confirm_execution: false }),
      });
      const seeded = (body as { bootstrap?: Bootstrap }).bootstrap;
      if (seeded?.walkthrough) {
        setWalkthrough(seeded.walkthrough);
      }
      if (seeded?.guided_story) {
        setStory(seeded.guided_story);
      }
      setLoaded(true);
      await loadMatrix();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Showcase reset failed");
    } finally {
      setBusy(false);
    }
  }

  if (!status) {
    return error ? <ErrorBanner message={error} /> : <LoadingState label="Loading walkthrough…" />;
  }

  const primary = walkthrough.filter((step) => step.group !== "supporting");
  const supporting = walkthrough.filter((step) => step.group === "supporting");

  return (
    <div className="stack">
      <PageHeader
        kicker="Enterprise showcase"
        title={status.scenario ? `${status.scenario.company}` : "Labelled AI assurance walkthrough"}
        lede="Organizations deploy AI systems faster than they can govern and validate them. ThreatSight connects AI systems to requirements, controls, evidence, assurance tests, findings, remediation, and retest. Synthetic data is labelled. This is not live enterprise discovery, not a legal compliance result, and not a GRC replacement."
      />
      {status.scenario ? (
        <section className="onboard" aria-labelledby="scenario-title">
          <h2 id="scenario-title">{status.scenario.ai_system}</h2>
          <dl className="facts">
            <div>
              <dt>Company</dt>
              <dd>{status.scenario.company}</dd>
            </div>
            <div>
              <dt>Purpose</dt>
              <dd>{status.scenario.purpose}</dd>
            </div>
            <div>
              <dt>Risk</dt>
              <dd>{status.scenario.risk}</dd>
            </div>
            <div>
              <dt>Control</dt>
              <dd>
                {status.scenario.control_identifier}: {status.scenario.control}
              </dd>
            </div>
            <div>
              <dt>Technical identifier</dt>
              <dd>
                {status.scenario.inventory_name} · labelled synthetic {String(status.scenario.labelled_synthetic)}. Not a
                second enterprise system.
              </dd>
            </div>
          </dl>
          <p className="muted">
            Legal claim {String(status.scenario.legal_compliance_claim)}. AUTH-01 still requires confirmation. Catalogs
            are incomplete. Autonomous attack {String(status.autonomous_attack)}.
          </p>
        </section>
      ) : (
        <p className="muted">
          AUTH-01 still requires confirmation. Catalogs are incomplete. Legal claim {String(status.legal_compliance_claim)}.
        </p>
      )}
      <ErrorBanner message={error} />
      <section>
        <h2>Assurance lifecycle</h2>
        <Lifecycle />
      </section>
      <p>
        <ConfirmButton
          label="Load labelled demo"
          confirmLabel="Confirm load labelled demo"
          disabled={busy}
          onConfirm={() => void bootstrap(false)}
        />{" "}
          <ConfirmButton
            label="Load demo and run AUTH-01"
            confirmLabel="Confirm AUTH-01 on the synthetic agent"
            disabled={busy}
            onConfirm={() => void bootstrap(true)}
          />{" "}
          <ConfirmButton
            className="btn secondary"
            label="Reset labelled showcase"
            confirmLabel="Confirm reset of showcase-origin records only"
            disabled={busy}
            onConfirm={() => void resetShowcase()}
          />
      </p>
      {loaded ? <p className="muted">Labelled demo records are present. Follow the story, then the primary loop.</p> : null}
      <section>
        <h2>What this demo shows</h2>
        <p className="muted">
          Initial test fails, unauthorized action is observed, evidence is captured, remediation is applied, retest
          passes. CTRL-002 on the synthetic agent only.
        </p>
        <ol className="story">
          {story.map((item) => (
            <li key={item.id}>
              <Link href={item.href}>{item.title}</Link>
              <div className="muted">{item.body}</div>
            </li>
          ))}
        </ol>
      </section>
      <section>
        <h2>Primary assurance loop</h2>
        <StepList steps={primary} />
      </section>
      <section>
        <h2>Supporting catalogs</h2>
        <StepList steps={supporting} />
      </section>
      <section>
        <h2>Control matrix</h2>
        {!matrix || matrix.items.length === 0 ? (
          <EmptyState
            title="No controls to matrix yet"
            detail="Load the labelled demo, then export Control | Requirement | Test | Result | Evidence | Owner | Framework | Freshness."
          />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Control</th>
                <th>Requirement</th>
                <th>Test</th>
                <th>Result</th>
                <th>Evidence</th>
                <th>Owner</th>
                <th>Framework</th>
                <th>Freshness</th>
              </tr>
            </thead>
            <tbody>
              {matrix.items.map((item) => (
                <tr key={item.control_id}>
                  <td>
                    <Link href={`/controls/${item.control_id}`}>{item.control}</Link>
                  </td>
                  <td>{item.requirement || "—"}</td>
                  <td>{item.test || "—"}</td>
                  <td>
                    {item.result ? <StatusPill value={item.result} tone={verdictTone(item.result)} /> : "—"}
                  </td>
                  <td>
                    {item.evidence ? <Link href={`/evidence/${item.evidence}`}>envelope</Link> : "—"}
                  </td>
                  <td>{item.owner}</td>
                  <td>{item.framework || "—"}</td>
                  <td>
                    <StatusPill value={item.freshness} tone={freshnessTone(item.freshness)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted">
          Freshness window is {status.evidence_fresh_days} days. Download JSON/CSV from <Link href="/exports">Exports</Link>.
        </p>
      </section>
    </div>
  );
}
