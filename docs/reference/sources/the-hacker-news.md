# The Hacker News — collection contract

| Field | Value |
| --- | --- |
| Role | `media_discovery` |
| Feed | `https://feeds.feedburner.com/TheHackersNews` (official site RSS) |
| Site | `https://thehackernews.com` |
| robots.txt | `Disallow:` empty for `*` (checked 2026-11-03); RSS preferred over HTML scrape |
| Auth | None |
| Storage | title, canonical URL, publication time, author, CVEs found in title/excerpt, bounded excerpt (≤500 chars), content hash |
| Forbidden | full article body, HTML, scripts, images, tracking params, paywalled content |

Media discovery cannot independently set vendor or government confirmation.
