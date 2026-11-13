# Shared-responsibility matrix

| Concern | ThreatSight product | Customer / design partner |
|---------|---------------------|---------------------------|
| Application code & charts | Provides | Reviews |
| Container images (private) | Builds | Pulls into private registry |
| Kubernetes / VM | Documents | Operates |
| TLS / DNS / ingress | Documents | Owns |
| PostgreSQL HA/backup off-host | Documents procedures | Owns destination & RPO/RTO |
| OIDC IdP | Integrates | Owns users/groups |
| Secrets | Consumes mounts | Creates/rotates |
| Customer runner host | Documents | Installs/patches |
| Connector credentials | Stores encrypted references | Authorizes scopes |
| Legal / DPA | Provides placeholders only | Executes with counsel |
| Support SLA | None in Phase 3G | Defines escalation contacts |
