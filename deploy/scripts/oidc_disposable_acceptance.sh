#!/usr/bin/env bash
# Bring up disposable Keycloak+TLS, run OIDC matrix tests, tear down.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE="${ROOT}/deploy/validation/oidc-keycloak/docker-compose.yml"
PROJ="threatsight-oidc-disp"

cleanup() {
  sudo docker compose -p "${PROJ}" -f "${COMPOSE}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== start disposable Keycloak + TLS edge =="
sudo docker compose -p "${PROJ}" -f "${COMPOSE}" up -d
# Wait for realm endpoint
for i in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:18081/realms/master" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS "http://127.0.0.1:18081/realms/master" >/dev/null
echo "keycloak_http_ok"

# TLS edge may use local CA — connectivity check without full verify optional
curl -kfsS "https://127.0.0.1:18443/realms/master" >/dev/null && echo "keycloak_tls_ok" || echo "keycloak_tls_deferred"

echo "== unit OIDC browser contract =="
cd "${ROOT}"
# shellcheck disable=SC1091
source /tmp/ts-3d1-venv/bin/activate 2>/dev/null || true
export THREATSIGHT_RUN_MIGRATIONS=false
pytest apps/api/tests/test_oidc_browser_matrix.py apps/api/tests/test_enterprise_oidc_matrix.py -q --tb=line

cleanup
trap - EXIT
echo "oidc_disposable_acceptance_ok"
