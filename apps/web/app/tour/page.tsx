"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect } from "react";

const STEPS = [
  {
    title: "An external change is observed",
    href: "/threats",
    body: "Cloudflare measurements and public advisories are global observations. They are not verified attacks against this organization.",
  },
  {
    title: "ThreatSight checks known technology",
    href: "/services",
    body: "Customer ordering has an identifier match to a synthetic asset. The match is a candidate, not proof of exploitation.",
  },
  {
    title: "The technology belongs to a business service",
    href: "/services",
    body: "The matched technology is a member of Customer ordering. Privileged administration and Remote access are the other synthetic reference services.",
  },
  {
    title: "Path evidence stays labelled",
    href: "/paths",
    body: "A configured dependency can be shown. It is not verified packet delivery, and missing reachability stays unknown.",
  },
  {
    title: "Control readiness is separate",
    href: "/controls",
    body: "A configured control is not observed effectiveness. The reference control still needs an owner.",
  },
  {
    title: "Someone owns the next action",
    href: "/actions",
    body: "The next step is to validate the recorded version and assign an owner. Opening the page does not create an action.",
  },
  {
    title: "Evidence stays attached",
    href: "/evidence",
    body: "The advisory, match, path, and control remain available for review. Synthetic reference evidence is not live-verified.",
  },
  {
    title: "Live connectors would replace this reference",
    href: "/briefing",
    body: "A customer deployment would keep the same decision chain and replace these synthetic records with authorized, read-only collection.",
  },
];

function Tour() {
  const params = useSearchParams();
  const router = useRouter();
  const requested = Number(params.get("step") || "1");
  const step = Number.isInteger(requested) && requested >= 1 && requested <= STEPS.length ? requested : 1;
  const item = STEPS[step - 1];

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      if (target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return;
      if (event.key === "ArrowRight" && step < STEPS.length) router.push(`/tour?step=${step + 1}`);
      if (event.key === "ArrowLeft" && step > 1) router.push(`/tour?step=${step - 1}`);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [router, step]);

  return (
    <article className="stack">
      <p className="kicker">Guided tour</p>
      <h1>Know what matters. Prove you are ready.</h1>
      <p>ThreatSight connects external threat developments to cloud, identities, networks, business services, and evidence, while showing what is known, what is uncertain, and what requires verification.</p>
      <p role="status">Step {step} of {STEPS.length}. {item.title}</p>
      <h2>{item.title}</h2>
      <p>{item.body}</p>
      <p><Link href={item.href}>Open this part of the product</Link></p>
      {step === 3 ? (
        <p>The other reference services are <Link href="/services">Privileged administration</Link> and <Link href="/services">Remote access</Link>. Both stay labelled synthetic.</p>
      ) : null}
      <nav aria-label="Tour">
        {step > 1 ? <Link href={`/tour?step=${step - 1}`}>Previous</Link> : <span>Previous</span>}
        {" · "}
        {step < STEPS.length ? <Link href={`/tour?step=${step + 1}`}>Next</Link> : <span>Next</span>}
        {" · "}
        <Link href="/">Exit tour</Link>
      </nav>
      {step === STEPS.length ? (
        <section>
          <h2>Evaluate ThreatSight with your environment</h2>
          <p>A design-partner evaluation would cover one cloud platform, one identity platform, two network or edge platforms, and three critical business services. Collection would be read-only, explicitly authorized, and performed by a customer-resident runner. Evidence would be accepted jointly.</p>
          <p>Contact the ThreatSight team to discuss a design-partner evaluation.</p>
        </section>
      ) : null}
    </article>
  );
}

export default function TourPage() {
  return (
    <Suspense fallback={<p role="status">Loading the guided tour</p>}>
      <Tour />
    </Suspense>
  );
}
