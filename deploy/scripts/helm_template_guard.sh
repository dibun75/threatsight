#!/usr/bin/env bash
# Render Helm chart and fail if secret-like material appears.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHART="${ROOT}/deploy/helm/threatsight"
OUT="$(mktemp)"
trap 'rm -f "${OUT}"' EXIT

helm lint "${CHART}"
helm template threatsight "${CHART}" \
  --set publicOrigin=https://threatsight.example \
  --set config.oidc.issuer=https://login.example/realms/threatsight \
  --set config.oidc.audience=threatsight-api \
  --set config.oidc.clientId=threatsight \
  --set config.oidc.authorizationEndpoint=https://login.example/auth \
  --set config.oidc.tokenEndpoint=https://login.example/token \
  --set config.oidc.jwksUri=https://login.example/certs \
  > "${OUT}"

# Must reference secrets by name, not embed values.
grep -q 'secretKeyRef' "${OUT}"
grep -q 'threatsight-signing-key' "${OUT}"
grep -q 'threatsight-radar' "${OUT}"

# Forbidden patterns in rendered output.
if grep -Eiw 'begin private key|changeme-dev-only|client_secret:\s*\"[^\"]+\"|password:\s*\"[^\"]{8,}\"' "${OUT}"; then
  echo "FAIL secret-like material in helm template" >&2
  exit 1
fi

# Isolation: signing key only on evidence-signer; radar/vulncheck only on intel-worker.
python3 - <<'PY' "${OUT}"
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
docs = text.split("---")
for doc in docs:
    if "kind: Deployment" not in doc:
        continue
    name = "unknown"
    for line in doc.splitlines():
        if line.strip().startswith("name:") and "threatsight" in line:
            name = line.split(":",1)[1].strip()
            break
    if "evidence-signer" in name or "component: evidence-signer" in doc:
        assert "evidence_signing_key" in doc or "signing-key" in doc
        assert "cloudflare_radar_token" not in doc and "vulncheck_token" not in doc
    if "intel-worker" in name or "component: intel-worker" in doc:
        assert "cloudflare_radar_token" in doc or "radar" in doc
        assert "evidence_signing_key" not in doc
    if "component: api" in doc and "Deployment" in doc:
        assert "evidence_signing_key" not in doc
        assert "cloudflare_radar_token" not in doc
print("helm_template_guard_ok")
PY
