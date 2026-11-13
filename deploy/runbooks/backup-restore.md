# Backup and restore

## Contract

- PostgreSQL custom-format (`-Fc`) dump
- SHA-256 integrity checksum in sidecar metadata
- Schema version recorded
- **Excluded:** Radar/VulnCheck tokens, evidence signing private key, OIDC client secret, env files
- **Retained:** application data, evidence public metadata, signatures (verification material)

RPO/RTO are **customer-selected objectives**, not product guarantees.

## Backup

```bash
deploy/scripts/backup.sh ./backups
# Encrypt before off-host transfer with a customer-managed key.
```

## Restore verification

```bash
deploy/scripts/restore_verify.sh ./backups/threatsight-….dump ./backups/threatsight-….meta.json
```

Uses a disposable clone database by default. Do not restore over the live reference database without an explicit maintenance window.
