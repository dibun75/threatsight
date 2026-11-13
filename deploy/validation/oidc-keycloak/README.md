# Disposable Keycloak (Phase 3G)

```bash
sudo docker compose -p threatsight-oidc-disp -f deploy/validation/oidc-keycloak/docker-compose.yml up -d
# Admin UI: https://127.0.0.1:18443 (trust local Caddy cert) or http://127.0.0.1:18081
# Run pytest OIDC browser/API suite, then:
sudo docker compose -p threatsight-oidc-disp -f deploy/validation/oidc-keycloak/docker-compose.yml down -v
```

Does not alter live reference auth. Uses disposable credentials only.
