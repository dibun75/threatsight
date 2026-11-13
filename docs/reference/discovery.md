# AI discovery

M5 discovery is an authorized fetch of a labelled synthetic public site, not a vulnerability scanner and not an unrestricted crawl.

## Workflow

```text
URL / public source
        ↓
Discovery (allow-listed GET, robots.txt)
        ↓
AI asset identification
        ↓
Document and signal extraction (heuristic candidates)
        ↓
Human review
        ↓
Map to requirements and controls (optional, informational)
        ↓
Assurance visibility
```

## Runtime bounds

- Default target: Compose DNS `demo-site:8091`, not published on the host.
- Allow-list: hostname of `THREATSIGHT_DEMO_SITE_URL` (default `demo-site`).
- `confirm_execution`, sandbox default, kill switch, 24-hour source authorization.
- robots.txt honored. `/internal` is disallowed on the demo site.
- HTTP(S) GET only. Size cap, max five pages, two redirects re-checked against the allow-list, 20 scans/minute.
- Adapter: `http` in Docker, `inprocess` for isolated tests.

## Evidence

A pending signal stores page URL, quote, extracted statement, content hash, and review status. Approval creates an accepted document-type evidence record with provenance `url + hash + timestamp`. That is not a legal compliance result and does not auto-set `VALIDATED` or `COMPLIANT`.
