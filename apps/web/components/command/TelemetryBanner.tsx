"use client";

import { useEffect, useState } from "react";

import { SourceTime } from "@/components/command/SourceTime";
import { api } from "@/lib/api";
import { humanize } from "@/lib/humanize";
import { presentTelemetry, telemetryHeadline, type PresentationState } from "@/lib/telemetry-state";

export type ActivitySnapshot = {
  state: string;
  connected?: boolean;
  primary?: {
    label?: string;
    normalization?: string | null;
    units?: string | null;
    source_updated_at?: string | null;
    comparison?: string;
  };
  windows?: Record<string, { normalization?: string | null; units?: string | null; source_updated_at?: string | null; items?: unknown[] }>;
};

export function useActivity() {
  const [activity, setActivity] = useState<ActivitySnapshot | null>(null);
  const [pending, setPending] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    api<ActivitySnapshot>("/api/v1/telemetry/activity", { signal: controller.signal })
      .then(setActivity)
      .catch(() => setActivity(null))
      .finally(() => setPending(false));
    return () => controller.abort();
  }, []);
  const hasSnapshot = Boolean(activity?.windows?.["24h"]?.source_updated_at || activity?.primary?.source_updated_at);
  const state = presentTelemetry(pending ? null : { state: activity?.state, hasSnapshot }, pending);
  return { activity, state, pending };
}

export function TelemetryBanner({ state, activity, window = "24h" }: { state: PresentationState; activity: ActivitySnapshot | null; window?: string }) {
  if (state === "loading") return <p className="skeleton" aria-busy="true">Loading global activity.</p>;
  const view = activity?.windows?.[window];
  const updated = view?.source_updated_at ?? activity?.primary?.source_updated_at;
  const normalization = view?.normalization ?? activity?.primary?.normalization;
  const units = view?.units ?? activity?.primary?.units;
  return (
    <div>
      <p>{telemetryHeadline(state)}</p>
      {state === "current" || state === "stale" || state === "failed_with_last_known_good" ? (
        <p>
          {activity?.primary?.label ?? "Cloudflare-observed mitigated Layer 7 requests"}
          {" · "}
          {window}
          {normalization ? ` · ${humanize(normalization)}` : ""}
          {units ? ` · ${units}` : ""}
          {updated ? <> · <SourceTime value={updated} /></> : null}
        </p>
      ) : null}
      {state === "stale" && updated ? <p>Last observation <SourceTime value={updated} />. Stale.</p> : null}
    </div>
  );
}
