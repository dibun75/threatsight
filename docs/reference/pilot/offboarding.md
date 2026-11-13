# Removal / offboarding procedure

1. Disable connectors and revoke runner credentials
2. Revoke OIDC client or remove redirect URI
3. Export customer-owned evidence/manifests if requested (no private signing key)
4. Final encrypted backup to customer destination
5. Scale workers to zero; uninstall Helm release / Compose project
6. Drop or return database per customer instruction
7. Confirm secrets deleted from customer secret store
8. Remove temporary accounts; record completion in ops log
9. Do **not** retain customer private data on the reference host

This procedure is operational guidance, not a legal termination clause.
