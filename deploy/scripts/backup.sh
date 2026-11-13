#!/usr/bin/env bash
# ThreatSight pilot backup — PostgreSQL custom-format dump + checksum + metadata.
# Does not include tokens, signing private keys, or .env files.
# RPO/RTO are customer-selected objectives — not product guarantees.
set -euo pipefail

DEST_DIR="${1:-./backups}"
CONTAINER="${THREATSIGHT_POSTGRES_CONTAINER:-threatsight-postgres}"
DB_NAME="${THREATSIGHT_DB_NAME:-threatsight}"
DB_USER="${THREATSIGHT_DB_USER:-threatsight}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${DEST_DIR}"
DUMP="${DEST_DIR}/threatsight-${STAMP}.dump"
META="${DEST_DIR}/threatsight-${STAMP}.meta.json"

sudo docker exec "${CONTAINER}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" -Fc -f "/tmp/threatsight-${STAMP}.dump"
sudo docker cp "${CONTAINER}:/tmp/threatsight-${STAMP}.dump" "${DUMP}"
sudo docker exec "${CONTAINER}" rm -f "/tmp/threatsight-${STAMP}.dump"

SUM="$(sha256sum "${DUMP}" | awk '{print $1}')"
SCHEMA="$(sudo docker exec "${CONTAINER}" psql -U "${DB_USER}" -d "${DB_NAME}" -tAc 'SELECT version_num FROM alembic_version' | tr -d '[:space:]')"

# Optional encryption before off-host transfer (disposable key via BACKUP_ENCRYPT_KEY_FILE).
ENC=""
if [[ -n "${BACKUP_ENCRYPT_KEY_FILE:-}" ]]; then
  ENC="${DUMP}.enc"
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
    -in "${DUMP}" -out "${ENC}" -pass "file:${BACKUP_ENCRYPT_KEY_FILE}"
  ENC_SUM="$(sha256sum "${ENC}" | awk '{print $1}')"
  echo "encrypted=${ENC}"
  echo "encrypted_sha256=${ENC_SUM}"
fi

cat > "${META}" <<EOF
{
  "schema_version": "${SCHEMA}",
  "created_at": "${STAMP}",
  "format": "postgresql-custom",
  "sha256": "${SUM}",
  "encrypted": $([ -n "${ENC}" ] && echo true || echo false),
  "excludes": ["tokens", "signing_private_key", "oidc_client_secret", "env_files"],
  "claims": "pilot backup artifact; not a DR/SLA guarantee; RPO/RTO customer-selected"
}
EOF

echo "backup=${DUMP}"
echo "sha256=${SUM}"
echo "schema=${SCHEMA}"
