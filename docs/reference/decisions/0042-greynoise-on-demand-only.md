# ADR 0042 — GreyNoise is on-demand enrichment only

## Status

Accepted for P3K-09 engineering.

## Decision

- ThreatSight may query only a single operator-selected, public IPv4 address.
- The Community endpoint is `GET https://api.greynoise.io/v3/community/{ip}`.
- No scheduler, background sweep, bulk lookup, map population, or automatic lookup of every DShield/ThreatFox indicator is permitted.
- Results are cached by workspace and IP to conserve the external quota; explicit refresh is administrator-only and rate-limited.
- `noise`, `riot`, `classification`, provider/name, link, and `last_seen` remain source-reported fields.
- `noise=true` means GreyNoise observed scanning; it does not identify an attacker or prove targeting, reachability, exploitation, compromise, or customer impact.
- Private, loopback, link-local, multicast, reserved, and metadata addresses fail closed before network access.
- Any API key is optional, file-mounted to the outbound intelligence worker only, and never sent to the browser or central API process.

## Rationale

The Community API is a free, rate-limited IP lookup service. It is not a bulk telemetry feed. Treating it as a map source would exhaust quotas, misrepresent its contract, and weaken source separation.

## Initial limits

- One IPv4 address per request.
- Ten lookups per workspace per day inside ThreatSight, regardless of upstream allowance.
- Seven-day cache unless an administrator explicitly refreshes.
- No automatic action or severity change from GreyNoise classification alone.
