# Product experience

Status: P2-15 deployed this shell on the public web. The reference graph is synthetic and fixture-tested.

## Positioning

ThreatSight is continuous hybrid security readiness. The outcome is: know what matters, and prove you are ready.

ThreatSight connects global threat intelligence to cloud, identities, firewalls, VPNs, and critical services. It shows what is relevant, what remains uncertain, and which controls require verification.

AI assurance is one control domain. It is not the product headline.

Words that are not used as product claims: single pane of glass, complete visibility, real-time unless a source is real-time, secure, safe, compliant, compromised, vulnerable for a candidate match, reachable for a configured path, or automatic remediation.

## Audit of the previous interface

Primary navigation was Dashboard, Guided demo, AI systems, Threat radar, Threats, Findings, Tests, and Evidence, plus a collapsed catalog of Controls, Requirements, Documents, Frameworks, Reports, Audit, Discovery, and Ops.

`/exposure` redirected to `/findings`.

Styles lived in one stylesheet with paper, ink, and teal tokens, named IBM Plex and Newsreader without a bundled font file. State used color pills. The dashboard led with AI systems and an assurance meter. Radar already separated geography roles. Counts on the dashboard came from the dashboard API and included provenance objects, but the page did not always show the timestamp beside the count.

## Route mapping

| Previous route | New place |
| --- | --- |
| `/` | Overview |
| `/radar` | Radar |
| `/exposure` | Exposure overview. The redirect to findings is removed |
| `/assurance`, `/systems` | Assurance |
| `/findings` | Actions |
| `/evidence` | Evidence |
| `/controls`, `/requirements`, `/documents`, `/frameworks`, `/audit`, `/discovery`, `/ops`, `/exports`, `/threats`, `/showcase` | Administration. Pages stay |

## Decision chain

Overview, Exposure, and match detail follow the same questions: what changed, why it might affect this workspace, which services and assets are involved, what is known or missing, which controls need verification, who should act, and whether a response was verified. Assurance verdicts are not changed from Exposure.

## Visual system

| Token | Value | Use |
| --- | --- | --- |
| Ink | `#182026` | Text |
| Navigation | `#243746` | Shell |
| Canvas | `#F4F1EA` | Page background |
| Surface | `#FFFFFF` | Cards and tables |
| Border | `#CBD2D6` | Rules |
| Secondary text | `#5D6970` | Supporting copy |
| Teal | `#216E63` | Verified with current evidence |
| Blue | `#2B5C88` | Information and selection |
| Ochre | `#8A6400` | Partial, stale, uncertain |
| Brick | `#A33A33` | Confirmed urgent facts only |

Type is a local system stack. No runtime font request. Counts and times use tabular numerals. Times are shown in UTC. State uses a text label. Color is not the only signal.

## Truth labels

`synthetic`, `fixture tested`, `live verified`, `observed`, `configured`, `inferred`, `manual`, `partial`, `stale`, `unknown`, `conflicting`, `unsupported`, and `replayed snapshot` each have a visible name and an accessible description.

A candidate match is not labelled vulnerable. A configured path is not labelled reachable. Zero candidates is not labelled safe when no snapshot exists.

## Verification

Checked on a temporary API at `127.0.0.1:8014` and a production web build at `127.0.0.1:3014`, using database `threatsight_p214` only. The preserved database stayed at `0014_exposure_graph`. The public web container was not changed.

The walkthrough showed the default workspace, fixture-tested and synthetic labels, Radar events that are not called incidents, customer ordering with an identifier match for CVE-2024-1001, a version-supported candidate, conflicting and not-applicable rows, a path step list with a table alternative, configured evidence that is not described as packet delivery, a not-applicable review recorded by the workspace administrator, and connector cards that say live connection was not validated. A 390-pixel width showed the menu button and a single-column summary. No combined score is shown.

Web unit tests passed. `tsc` and `next build` passed. `npm audit` reported no production vulnerabilities. No new UI framework was added. No automated WCAG scanner is installed; the checks above are from the browser, semantic headings, labels, and the skip link.

The disposable correlation run also included catalog advisories, so the match count is larger than the synthetic fixture alone. That count comes from the API.
