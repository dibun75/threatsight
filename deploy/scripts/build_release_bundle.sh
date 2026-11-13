#!/usr/bin/env bash
# Build a private Phase 3F release bundle. Do not push images/charts publicly.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD)"
OUT="${1:-${ROOT}/deploy/release/out/threatsight-pilot-${COMMIT}}"
mkdir -p "${OUT}/sbom" "${OUT}/scans" "${OUT}/chart" "${OUT}/compose" "${OUT}/docs"

echo "commit=${COMMIT}"
cp -a "${ROOT}/deploy/compose/hardened/." "${OUT}/compose/"
cp -a "${ROOT}/deploy/runbooks" "${OUT}/docs/runbooks"
cp -a "${ROOT}/deploy/config" "${OUT}/docs/config"
cp "${ROOT}/deploy/profiles.md" "${ROOT}/deploy/availability.md" "${ROOT}/deploy/observability/metrics.md" "${OUT}/docs/"
cp "${ROOT}/docs/reference/decisions/0040-enterprise-pilot-packaging.md" "${OUT}/docs/"

helm package "${ROOT}/deploy/helm/threatsight" -d "${OUT}/chart"

API_IMAGE="${THREATSIGHT_API_IMAGE:-threatsight-api:837e39a}"
WEB_IMAGE="${THREATSIGHT_WEB_IMAGE:-threatsight-web:837e39a}"

{
  echo "tool=syft"
  syft version 2>&1 | head -5
} > "${OUT}/sbom/tool.txt"
syft "${API_IMAGE}" -o spdx-json > "${OUT}/sbom/api.spdx.json" || echo "syft_api_skipped" > "${OUT}/sbom/api.skipped"
syft "${WEB_IMAGE}" -o spdx-json > "${OUT}/sbom/web.spdx.json" || echo "syft_web_skipped" > "${OUT}/sbom/web.skipped"
syft "dir:${ROOT}/deploy/helm/threatsight" -o spdx-json > "${OUT}/sbom/helm.spdx.json" || true

{
  echo "tool=trivy"
  trivy version 2>&1 | head -3
} > "${OUT}/scans/tool.txt"
trivy image --severity CRITICAL,HIGH --format table -o "${OUT}/scans/api-vuln.txt" "${API_IMAGE}" || true
trivy image --scanners secret --format table -o "${OUT}/scans/api-secret.txt" "${API_IMAGE}" || true
trivy config --severity CRITICAL,HIGH --format table -o "${OUT}/scans/helm-misconfig.txt" "${ROOT}/deploy/helm/threatsight" || true
trivy fs --scanners secret --format table -o "${OUT}/scans/repo-secret.txt" "${ROOT}/deploy" || true

API_DIGEST="$(sudo docker image inspect "${API_IMAGE}" --format '{{index .RepoDigests 0}}' 2>/dev/null || echo "local-only")"
WEB_DIGEST="$(sudo docker image inspect "${WEB_IMAGE}" --format '{{index .RepoDigests 0}}' 2>/dev/null || echo "local-only")"

cat > "${OUT}/RELEASE_MANIFEST.json" <<EOF
{
  "product": "ThreatSight",
  "phase": "3F",
  "commit": "$(git -C "${ROOT}" rev-parse HEAD)",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "images": {
    "api": {"ref": "${API_IMAGE}", "digest": "${API_DIGEST}"},
    "web": {"ref": "${WEB_IMAGE}", "digest": "${WEB_DIGEST}"}
  },
  "limitations": "Pilot packaging only. Not commercial production readiness, HA, SLA, support commitment, or compliance certification.",
  "support_escalation": "PLACEHOLDER — customer-defined escalation path",
  "registry": "private-only; not published by this script"
}
EOF

(
  cd "${OUT}"
  find . -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

echo "bundle=${OUT}"
