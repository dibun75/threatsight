# Siemens ProductCERT — collection contract

| Field | Value |
| --- | --- |
| Role | `vendor_authority` |
| Feed index | `https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json` |
| Advisory | `https://cert-portal.siemens.com/productcert/csaf/ssa-{id}.json` |
| Format | CSAF 2.0 JSON (TLP:WHITE / TLP:CLEAR) |
| Auth | None for TLP:WHITE feed |
| Redistribution | Subject to Siemens ProductCERT terms of use; store normalized metadata, not republish HTML |
| Timestamps | `document.tracking.initial_release_date`, `current_release_date` |
| Stable ID | `document.tracking.id` (SSA-…) |
| Rate | Bounded; conditional requests when ETag present |
| Failure | Preserve last-known-good documents |

Parser uses structured `product_status`, `product_tree`, and `remediations`. Ambiguous prose → `unknown`.
