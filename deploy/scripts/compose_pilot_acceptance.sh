#!/usr/bin/env bash
# Hardened Compose disposable acceptance. Isolated project; does not disturb live reference.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJ="threatsight-pilot-disp"
WORKDIR="$(mktemp -d /tmp/threatsight-pilot-XXXX)"
COMPOSE="${ROOT}/deploy/compose/hardened/docker-compose.disposable.yml"
API_IMAGE="${THREATSIGHT_API_IMAGE:-threatsight-api:837e39a}"
WEB_IMAGE="${THREATSIGHT_WEB_IMAGE:-threatsight-web:837e39a}"

cleanup() {
  sudo docker compose -p "${PROJ}" -f "${COMPOSE}" --project-directory "${WORKDIR}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
# NOTE: image tags are written to WORKDIR/.env (sudo drops caller exports).
trap cleanup EXIT

mkdir -p "${WORKDIR}/secrets"
cp "${ROOT}/deploy/compose/hardened/Caddyfile.disposable" "${WORKDIR}/Caddyfile.disposable"
umask 077
printf '%s' 'postgresql+psycopg://pilotuser:pilot-disp-db-secret-9f3a@postgres:5432/threatsight' > "${WORKDIR}/secrets/database_url"
printf '%s' 'disposable-oidc-secret' > "${WORKDIR}/secrets/oidc_client_secret"
printf '%s' 'disposable-radar' > "${WORKDIR}/secrets/cloudflare_radar_token"
printf '%s' 'disposable-vulncheck' > "${WORKDIR}/secrets/vulncheck_token"
python3 - <<'PY' "${WORKDIR}/secrets/evidence_signing_key"
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key = Ed25519PrivateKey.generate()
Path(sys.argv[1]).write_bytes(
    key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)
PY
# Non-root containers (uid 10001) must be able to read Compose file-secrets.
# Swarm/K8s secret mounts are typically 0444 under /run/secrets (allowed by config).
chmod 644 "${WORKDIR}/secrets/"*

echo "== compose up (isolated project ${PROJ}) =="
# Write image pins into project .env so sudo docker compose substitution works.
cat > "${WORKDIR}/.env" <<EOF
THREATSIGHT_API_IMAGE=${API_IMAGE}
THREATSIGHT_WEB_IMAGE=${WEB_IMAGE}
EOF
dc() { sudo docker compose -p "${PROJ}" -f "${COMPOSE}" --project-directory "${WORKDIR}" "$@"; }
dc up -d --wait || dc up -d
sleep 20

PG_CID="$(dc ps -q postgres)"
if sudo docker port "${PG_CID}" 2>/dev/null | grep -q .; then
  echo "FAIL postgres published on host" >&2
  exit 1
fi
echo "postgres_not_published_ok"

API="$(dc ps -q api || true)"
INTEL="$(dc ps -q intel-worker || true)"
SIGNER="$(dc ps -q evidence-signer || true)"
if [[ -n "${API}" ]] && sudo docker inspect "${API}" --format '{{json .Mounts}}' | grep -q evidence_signing_key; then
  echo "FAIL signing key mounted on api" >&2
  exit 1
fi
if [[ -n "${INTEL}" ]] && sudo docker inspect "${INTEL}" --format '{{json .Mounts}}' | grep -q evidence_signing_key; then
  echo "FAIL signing key on intel" >&2
  exit 1
fi
if [[ -n "${SIGNER}" ]] && sudo docker inspect "${SIGNER}" --format '{{json .Mounts}}' | grep -q cloudflare_radar_token; then
  echo "FAIL radar on signer" >&2
  exit 1
fi
echo "secret_isolation_ok"

curl -fsS "http://127.0.0.1:18080/health" && echo " api_health_ok" || {
  echo "api logs:"; dc logs api --tail 40 || true
  exit 1
}

BDIR="${WORKDIR}/backups"
mkdir -p "${BDIR}"
KEY="${WORKDIR}/backup.key"
openssl rand -hex 32 > "${KEY}"
chmod 600 "${KEY}"
THREATSIGHT_POSTGRES_CONTAINER="${PG_CID}" THREATSIGHT_DB_USER=pilotuser \
  BACKUP_ENCRYPT_KEY_FILE="${KEY}" \
  "${ROOT}/deploy/scripts/backup.sh" "${BDIR}"
test -f "${BDIR}"/*.dump
test -f "${BDIR}"/*.dump.enc
echo "backup_encrypt_ok"

sudo docker inspect threatsight-api --format '{{.State.Health.Status}}' | grep -q healthy
if [ -n "${THREATSIGHT_EDGE_CONTAINER:-}" ]; then
  sudo docker inspect "${THREATSIGHT_EDGE_CONTAINER}" --format "{{.RestartCount}}" | grep -qx 0
fi
echo "live_reference_untouched_ok"

cleanup
trap - EXIT
echo "compose_pilot_acceptance_ok"
