# Landscape source register

Collected 2026-10-31. New vendor sources in this phase were not retrieved live.

| Source | URL | Format | Auth | Maturity | Notes |
| --- | --- | --- | --- | --- | --- |
| CISA KEV | existing Phase 1 locator | JSON | none | live_verified when `last_status=ok` | Reused. Not re-downloaded by Landscape. |
| FIRST EPSS | existing Phase 1 locator | JSON | none | live_verified when previously collected | Daily bulk CSV was not re-fetched in this phase. |
| CERT-SE, NCSC-FI, NSM, ENISA, CERT-EU | existing locators | Atom, RSS, or JSON | none | live_verified when previously collected | Reused. |
| CERT-IS, SAMSIK | manual | none | none | unsupported | No machine contract. |
| Microsoft MSRC CSAF | https://msrc.microsoft.com/csaf | CSAF | none | fixture_tested | Index was not retrieved. |
| Cisco OpenVuln | https://sec.cloudapps.cisco.com/security/center/resources/openvulnapi | API | registration | credential_required | No account was created. |
| Fortinet PSIRT | https://www.fortiguard.com/psirt | RSS | none | fixture_tested | Not retrieved. |
| Palo Alto advisories | https://security.paloaltonetworks.com/ | RSS | none | fixture_tested | Not retrieved. |
| AWS bulletins | https://aws.amazon.com/security/security-bulletins/rss/ | RSS | none | fixture_tested | Not retrieved. |
| Google Cloud bulletins | https://docs.cloud.google.com/support/bulletins | HTML | none | fixture_tested | No stable bulk contract was verified. |
| NVD CVE/CPE | https://nvd.nist.gov/developers/products | API | none | fixture_tested | No incremental window and no full dictionary download. |
| Juniper | https://support.juniper.net/support/security/ | none verified | none | unsupported | No bulk advisory contract is implemented. |

Phase 2.9 collected these official documents with production code. A fixture row from Phase 2.8 was not relabeled.

| Source | Retrieval URL | Format | Maturity |
| --- | --- | --- | --- |
| FIRST EPSS | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | daily gzip CSV | live_verified |
| NVD CVE 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | JSON, five records, seven-day window | live_verified |
| AWS bulletins | `https://aws.amazon.com/security/security-bulletins/rss/feed/` | RSS | live_verified |
| Fortinet PSIRT | `https://filestore.fortinet.com/fortiguard/rss/ir.xml` | RSS | live_verified |
| Palo Alto advisories | `https://security.paloaltonetworks.com/rss.xml` | RSS | live_verified |
| Microsoft MSRC | CSAF index is HTML; current CVRF exceeds 4MB | not collected | fixture_tested |
| Google Cloud | HTML bulletins; no verified machine feed | not collected | fixture_tested |
| Cisco OpenVuln | registration required | not collected | credential_required |
| Juniper | no verified bulk contract | not collected | unsupported |

The choropleth uses local Natural Earth 1:110m admin-0 countries, public domain. See `apps/web/public/geo/LICENSE.txt`. It does not call a tile service. EU and other non-country authorities are not drawn as a country. The map summarizes sourced advisory geography. It does not show attacks, attacker origin, victim counts, or national cyber risk.

Rate limits for sources that were not called are recorded as "not called during normal startup or a web request." Existing Phase 1 collectors keep their own fetch limits.
