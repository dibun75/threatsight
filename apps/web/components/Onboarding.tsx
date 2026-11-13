import Link from "next/link";

import { Lifecycle } from "@/components/Lifecycle";

export function Onboarding() {
  return (
    <section className="onboard" aria-labelledby="onboard-title">
      <h2 id="onboard-title">How a claim becomes evidence</h2>
      <p>
        The agent is asked to do something it should refuse. ThreatSight judges what the agent actually did to the
        underlying system, not what it said about itself: if the order really was cancelled, the test fails, however
        politely the model denied doing it.
      </p>
      <p>
        A failure opens a finding. Someone fixes the cause, then the same test runs again, and only that second pass
        closes the finding. Every run leaves a hashed record, so the answer can be re-checked later by someone who was
        not in the room.
      </p>
      <h3>Assurance lifecycle</h3>
      <Lifecycle />
      <p className="muted">
        Systems, requirements, controls, evidence, tests, findings, remediation, and retest are linked records, which is
        what makes the trail reconstructable. This is a prototype, not a GRC replacement. Start with the{" "}
        <Link href="/showcase">guided demo</Link>.
      </p>
    </section>
  );
}
