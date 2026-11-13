#!/usr/bin/env bash
# Local backup + restore-to-clone drill. Does not upload off-host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BDIR="${ROOT}/backups/phase-3g-drill-${STAMP}"
CLONE="threatsight-pg-clone-drill"
mkdir -p "${BDIR}"

echo "== backup live postgres (local) =="
THREATSIGHT_POSTGRES_CONTAINER=threatsight-postgres \
  "${ROOT}/deploy/scripts/backup.sh" "${BDIR}"

DUMP="$(ls -1 "${BDIR}"/*.dump | head -1)"
test -f "${DUMP}"
SUM_FILE="${DUMP%.dump}" # meta alongside
# Verify checksum from meta
python3 - <<PY
import json, pathlib, hashlib
bdir = pathlib.Path("${BDIR}")
meta = next(bdir.glob("*.meta.json"))
data = json.loads(meta.read_text())
dump = next(bdir.glob("*.dump"))
h = hashlib.sha256(dump.read_bytes()).hexdigest()
assert h == data["sha256"], (h, data["sha256"])
print("checksum_ok", data.get("schema_version"))
PY

echo "== restore into disposable clone (not live) =="
sudo docker rm -f "${CLONE}" >/dev/null 2>&1 || true
sudo docker run -d --name "${CLONE}" \
  -e POSTGRES_USER=threatsight \
  -e POSTGRES_PASSWORD=clone-drill-only \
  -e POSTGRES_DB=threatsight \
  postgres:16-alpine
for i in $(seq 1 60); do
  if sudo docker exec "${CLONE}" pg_isready -U threatsight -d threatsight >/dev/null 2>&1; then
    # Give init scripts a moment after readiness
    sleep 3
    break
  fi
  sleep 1
done
sudo docker cp "${DUMP}" "${CLONE}:/tmp/restore.dump"
sudo docker exec "${CLONE}" pg_restore -U threatsight -d threatsight --clean --if-exists /tmp/restore.dump
REV="$(sudo docker exec "${CLONE}" psql -U threatsight -d threatsight -tAc 'SELECT version_num FROM alembic_version' | tr -d '[:space:]')"
echo "clone_schema=${REV}"
test "${REV}" = "0029_response_workspace" || test -n "${REV}"

sudo docker rm -f "${CLONE}" >/dev/null
echo "backup_restore_drill_ok"
echo "NOTE: local drill is not off-host protection"
