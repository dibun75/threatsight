# Guided-demo vs controlled-pilot gates

These are **separate**. Passing guided demo does not imply controlled pilot readiness.

## Guided demo — `ready_for_guided_demo`

Founder-led demonstration on the reference installation.

Minimum:

1. HTTPS public origin (`https://threatsight.io`)
2. Deterministic authentication/logout (local owner OK for demo)
3. No anonymous product access
4. Secure / HttpOnly / SameSite cookies (`__Host-` in production)
5. No default database credentials
6. Synthetic data clearly labelled
7. Live public intelligence distinguished from customer claims
8. No customer-impact / compliance claims in UI copy
9. Healthy collectors and signer
10. Local backup taken and restore-to-clone verified
11. Basic monitoring/health check
12. Documented rollback to previous image + dump
13. Five-minute demonstration path
14. No secret exposure in UI/logs/demos
15. No serious accessibility defect on primary path
16. Usable at ~390px width

## Controlled pilot — `ready_for_controlled_pilot`

Customer-controlled data and infrastructure.

Additional minimum (beyond guided demo):

1. Generic OIDC complete browser flow proven (disposable IdP acceptable as evidence)
2. ≥2 recovery administrators **or** documented customer recovery model
3. Production classification with pilot profile contract
4. Unique DB credentials; customer-managed secret plan
5. Secure cookie contract behind customer TLS
6. Encrypted **off-host** backup destination confirmed by customer
7. Restore drill against that class of destination
8. Named tenant/workspace for the partner
9. Data-retention agreement (customer-signed — external)
10. Connector permissions agreed (external)
11. Customer runner in customer infrastructure (external)
12. Support/escalation contacts (placeholders until partner assigned)
13. Maintenance/upgrade window
14. Rollback + exit/removal procedure
15. Pilot success criteria
16. Approved DPA/legal documents (external — blocked until counsel/partner)

Anything requiring a real customer or paid external service remains **externally blocked**.
