# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Email **contact@threatsight.io** with:

- what you found and where (file, endpoint, version or commit),
- how to reproduce it,
- what an attacker could do with it.

You will get an answer within five working days. Fixes are released as soon as they are ready, and reporters are credited unless they ask not to be.

## Scope

In scope: the ThreatSight API, web app, demo-world service, the `threatsight-world` package, and the Docker images built from this repository.

Out of scope: the fictional demo data itself (it is meant to be attacked), denial of service against the public demo at threatsight.io, and findings that need a compromised host or a stolen owner password.

## Design notes for reviewers

- Sign-in uses scrypt password hashes and HMAC-signed session cookies; only the owner approves accounts.
- API tokens are read-only, stored as SHA-256 hashes, and cannot reach sign-in or owner routes.
- Webhook URLs, model API keys and alert secrets are stored in files with mode 0600 and never returned to a browser.
- The demo world has no database connection and only acts on in-memory fictional data.
