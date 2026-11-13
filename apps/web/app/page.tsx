import type { Metadata } from "next";
import Link from "next/link";


export const metadata: Metadata = {
  title: "ThreatSight — See which threats can reach what matters",
  description: "ThreatSight connects global threat change to your assets, business services, security controls, and the decisions your teams must make.",
  alternates: { canonical: "https://threatsight.io/" },
  openGraph: {
    title: "See which threats can reach what matters",
    description: "Live public intelligence, a synthetic enterprise reference, and evidence-backed control readiness.",
    url: "https://threatsight.io/",
    images: [{ url: "/og.svg", width: 1200, height: 630, alt: "ThreatSight command map" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "See which threats can reach what matters",
    description: "Live public intelligence and evidence-backed control readiness. The enterprise reference is synthetic.",
    images: ["/og.svg"],
  },
};

export default function HomePage() {
  return (
    <article className="stack landing">
      <p className="kicker">Live authoritative intelligence · Synthetic enterprise reference</p>
      <h1>See which threats can reach what matters—and prove your defenses are ready.</h1>
      <p>ThreatSight connects global threat change to your assets, business services, security controls, and the decisions your teams must make.</p>
      <div className="cta-row">
        <Link className="btn" href="/demo">Explore the command center</Link>
        <Link className="btn secondary" href="/login">Sign in</Link>
      </div>
      <figure>
        <svg viewBox="0 0 800 220" role="img" aria-label="Static product illustration. It is not a live attack map.">
          <title>ThreatSight product illustration</title>
          <rect width="800" height="220" fill="#102027" />
          <path d="M40 120 C160 40 280 180 400 100 C520 20 640 160 760 90" fill="none" stroke="#7d9aa6" strokeWidth="3" />
        </svg>
        <figcaption>Advisory geography and global observed activity are separate views. This illustration does not show either dataset.</figcaption>
      </figure>
      <section className="outcome-row">
        <article className="outcome-card">
          <h2>What changed</h2>
          <p>Authoritative advisories are collected outside the page and labeled by source. KEV, EPSS, and vendor severity stay separate.</p>
        </article>
        <article className="outcome-card">
          <h2>What it may reach</h2>
          <p>A product and version are compared with the synthetic enterprise, then with the service that depends on it.</p>
        </article>
        <article className="outcome-card">
          <h2>What is proven</h2>
          <p>A control shows its evidence and its gaps. A recorded pass is not a certificate, and a candidate path is not an attack.</p>
        </article>
      </section>
      <section>
        <h2>From an advisory to a control</h2>
        <ol className="path-row">
          <li className="observed">External advisory</li>
          <li className="configured">Product and version</li>
          <li className="configured">Enterprise asset</li>
          <li className="inferred">Possible path</li>
          <li className="observed">Critical service</li>
          <li className="unknown">Control and evidence</li>
        </ol>
        <p>Solid means observed, dashed means configured, dotted means inferred, and a double border means the join is not yet known.</p>
      </section>
      <section>
        <h2>How a customer would run it</h2>
        <p>A design-partner evaluation can use the customer’s cloud subscription, their data center, or this Docker reference. Connectors and secrets stay with the customer. This public site does not collect visitor details and does not claim that a customer environment is connected.</p>
        <p><Link href="/tour?step=7">Read the evaluation boundary</Link></p>
      </section>
    </article>
  );
}
