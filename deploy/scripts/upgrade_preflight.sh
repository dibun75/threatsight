#!/usr/bin/env bash
# Preflight checks before a pilot upgrade. Does not mutate the live stack.
set -euo pipefail

API_IMAGE="${1:?api image tag/digest required}"
WEB_IMAGE="${2:?web image tag/digest required}"

echo "checking images exist locally"
sudo docker image inspect "${API_IMAGE}" >/dev/null
sudo docker image inspect "${WEB_IMAGE}" >/dev/null

echo "checking live health (reference)"
for c in threatsight-api threatsight-web threatsight-intel-worker threatsight-evidence-signer; do
  status="$(sudo docker inspect "${c}" --format '{{.State.Health.Status}}' 2>/dev/null || echo missing)"
  echo "  ${c}=${status}"
done

echo "schema=$(sudo docker exec threatsight-postgres psql -U threatsight -d threatsight -tAc 'SELECT version_num FROM alembic_version' | tr -d '[:space:]')"
echo "preflight_ok"
echo "Next: take backup (deploy/scripts/backup.sh), run migrations on target, roll API/web, then workers/signer."
echo "Never automatically downgrade a production database."
