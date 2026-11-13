# Radar Source and Licensing Register

Status: Phase 1 implementation contract
Validated: 2026-10-30

This register is an engineering boundary, not legal advice. ThreatSight stores only the material allowed below, attributes every authority, preserves canonical links, and treats all source content as untrusted data. Authority jurisdiction never implies attacker origin, victim location, or target country.

## Automated sources

### CISA Known Exploited Vulnerabilities

- Authority/jurisdiction: US Cybersecurity and Infrastructure Security Agency, United States.
- Endpoint/format: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, JSON.
- Semantics: vulnerability records with confirmed exploitation and CISA publication/update dates.
- Geography: reporting authority jurisdiction only; globally applicable product data.
- Cadence: hourly.
- Use: KEV data is CC0 1.0; store normalized fields and source data. Do not imply CISA endorsement or reproduce DHS/CISA marks.
- Failure/retirement: preserve existing records; expose stale/failed health; investigate repeated `404/410` or schema failures before disabling.
- Storage: structured content, hashes, metadata, and links.

### FIRST EPSS

- Authority/jurisdiction: FIRST EPSS SIG; no geographic event meaning.
- Endpoint/format: `https://api.first.org/data/v1/epss`, JSON lookup API.
- Semantics: current exploitation probability and percentile for requested CVEs; scores are predictions, not observed exploitation.
- Geography: none.
- Cadence: after event synchronization and no more than daily for unchanged CVEs.
- Use: free public cybersecurity use; retain FIRST attribution and notices. API is for small lookups, so requests remain bounded to 100 CVEs.
- Failure/retirement: preserve last score/date and expose failure; never convert missing EPSS into zero risk.
- Storage: CVE, score, percentile, score date, source, and timestamps.

### NSM vulnerability advisories

- Authority/jurisdiction: Norwegian National Security Authority / NCSC Norway, Norway.
- Endpoint/format: `https://nsm.no/rss/sarbarhetsvarsler-fra-nsm/`, RSS/XML.
- Semantics: a shallow rolling selection of vulnerabilities, updates, and events considered relevant to Norwegian society.
- Geography: Norwegian reporting-authority relevance only; not proof of a Norwegian target, victim, infrastructure location, or attacker.
- Cadence: hourly; prior records are retained when they leave the feed.
- Use: no blanket redistribution licence was found. Attribute NSM and store metadata, identifiers, short factual excerpts, hashes, and canonical links only.
- Failure/retirement: preserve records and show stale/failed health; repeated invalid responses require operator review.
- Storage: metadata/excerpts and links, not full article text.

### CERT-SE public articles

- Authority/jurisdiction: CERT-SE at the Swedish National Cybersecurity Centre/FRA, Sweden.
- Endpoint/format: `https://www.cert.se/feed/atom.xml`, Atom/XML.
- Semantics: public CERT-SE articles; the feed updates when an article is published or revised.
- Geography: Swedish reporting-authority relevance only.
- Cadence: hourly.
- Use: subscription is explicitly supported, but no blanket redistribution licence was found. Attribute CERT-SE and store metadata, identifiers, short factual excerpts, hashes, and canonical links.
- Failure/retirement: preserve records and show stale/failed health; do not fall back to scraping.
- Storage: metadata/excerpts and links only.

### NCSC-FI vulnerability advisories

- Authority/jurisdiction: National Cyber Security Centre Finland / Traficom, Finland.
- Endpoint/format: `https://www.kyberturvallisuuskeskus.fi/feed/rss/fi/400`, RSS/XML.
- Semantics: Finnish authority vulnerability advisories, including publication/update metadata.
- Geography: Finnish reporting-authority relevance only; advisories may concern globally applicable products.
- Cadence: hourly.
- Use: the RSS directory does not expressly apply Traficom's open-data licence to the feed. Attribute NCSC-FI/Traficom and retain metadata, short factual excerpts, identifiers, hashes, and links.
- Failure/retirement: preserve records and show stale/failed health; do not scrape the website.
- Storage: metadata/excerpts and links only.

### ENISA EU Vulnerability Database

- Authority/jurisdiction: European Union Agency for Cybersecurity, European Union.
- Endpoint/format: fixed base `https://euvdservices.enisa.europa.eu/api/search`, paginated JSON with `page` bounded to 0–50 and `size` bounded to 100.
- Semantics: vulnerability records and updates from EUVD. ENISA website RSS is discontinued and is not used.
- Geography: EU-operated knowledge base; records are globally applicable and are not automatically EU incidents or targets.
- Cadence: hourly latest-page poll. Phase 1 does not claim complete historical backfill or a durable incremental cursor.
- Use: ENISA authorizes reproduction with source acknowledgement unless stated otherwise. Preserve third-party rights/notices and canonical source references.
- Failure/retirement: preserve records and expose partial/failed health; no website scraping fallback.
- Storage: normalized structured fields, factual excerpts, hashes, provenance, and links.

### CERT-EU security advisories

- Authority/jurisdiction: CERT-EU, constituency of EU institutions, bodies, offices, and agencies.
- Endpoint/format: `https://cert.europa.eu/publications/security-advisories-rss`, RSS/XML.
- Semantics: rolling numbered security advisories selected for CERT-EU constituents.
- Geography: constituency relevance only; not proof of an incident or target in EU territory.
- Cadence: hourly, serial, with conservative retry/backoff because the origin may rate-limit automation.
- Use: CC BY 4.0 unless stated otherwise. Attribute CERT-EU, identify normalization, and preserve third-party-rights limitations.
- Failure/retirement: preserve records and show stale/failed health; do not scrape the archive as a fallback.
- Storage: normalized fields, excerpts, hashes, provenance, attribution, and links.

## Metadata/manual-import boundaries

### SAMSIK / Sikkerdigital Denmark

The official service primarily distributes selected weekly alerts by email. An implicit website feed is neither documented as an advisory contract nor clearly licensed. Phase 1 stores only operator-supplied official metadata and canonical `https://www.sikkerdigital.dk/` links within the registered source domain. Automated scraping is prohibited.

### CERT-IS Iceland

CERT-IS publishes public vulnerability pages, but its advertised feed returned `404` during validation and no general reuse licence was found. Phase 1 stores only operator-supplied official metadata and canonical `https://cert.is/` links. Automated scraping is prohibited.

## Common ingestion rules

- Fixed HTTPS origins and paths; callers cannot provide fetch destinations.
- Redirects are rejected unless the destination is an explicitly registered canonical endpoint.
- Twenty-second timeout, 8 MiB response limit, validated content type, and safe XML/JSON parsing.
- Parser fixtures, versioned normalization, payload/event hashes, timestamps, confidence, and limitations.
- Idempotent upsert by source plus external identity; individual source events are never deleted by clustering.
- Source HTML is reduced to plain text and never rendered as executable markup.
- `404/410`, repeated schema failures, or a documented retirement trigger operator review; existing records remain available with degraded source health.
- Metadata/manual import accepts no file, script, credential, authorization field, or arbitrary fetch URL.
