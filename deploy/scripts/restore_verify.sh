#!/usr/bin/env bash
# Restore a ThreatSight dump into a disposable database and verify schema/checksum.
# Never points at the live reference database by default.
set -euo pipefail

DUMP="${1:?dump path required}"
META="${2:-}"
CLONE_DB="${THREATSIGHT_CLONE_DB:-threatsight_restore_clone}"
CONTAINER="${THREATSIGHT_POSTGRES_CONTAINER:-threatsight-postgres}"
DB_USER="${THREATSIGHT_DB_USER:-threatsight}"

if [[ ! -f "${DUMP}" ]]; then
  echo "missing dump: ${DUMP}" >&2
  exit 2
fi

EXPECTED=""
if [[ -n "${META}" && -f "${META}" ]]; then
  EXPECTED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "${META}")"
  ACTUAL="$(sha256sum "${DUMP}" | awk '{print $1}')"
  if [[ "${EXPECTED}" != "${ACTUAL}" ]]; then
    echo "checksum mismatch" >&2
    exit 3
  fi
fi

sudo docker exec "${CONTAINER}" psql -U "${DB_USER}" -d postgres -v ON_ERROR_STOP=1 \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${CLONE_DB}' AND pid <> pg_backend_pid();" \
  -c "DROP DATABASE IF EXISTS ${CLONE_DB};" \
  -c "CREATE DATABASE ${CLONE_DB} OWNER ${DB_USER};"

sudo docker cp "${DUMP}" "${CONTAINER}:/tmp/restore.dump"
sudo docker exec "${CONTAINER}" pg_restore -U "${DB_USER}" -d "${CLONE_DB}" --clean --if-exists /tmp/restore.dump
SCHEMA="$(sudo docker exec "${CONTAINER}" psql -U "${DB_USER}" -d "${CLONE_DB}" -tAc 'SELECT version_num FROM alembic_version' | tr -d '[:space:]')"
echo "restore_ok schema=${SCHEMA} clone=${CLONE_DB}"
echo "NOTE: signing private key and tokens are NOT restored from this dump; re-provision secrets separately."
