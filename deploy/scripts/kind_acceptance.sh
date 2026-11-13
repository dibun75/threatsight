#!/usr/bin/env bash
# Disposable kind acceptance for Phase 3F. Does not touch live Compose or tunnel.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CTX="${KIND_CONTEXT:-kind-threatsight-p3f}"
NS="threatsight-pilot-$$"
API_IMAGE="${THREATSIGHT_API_IMAGE:-threatsight-api:p3f-disp}"
WEB_IMAGE="${THREATSIGHT_WEB_IMAGE:-threatsight-web:837e39a}"
API_TAG="${API_IMAGE##*:}"
WEB_TAG="${WEB_IMAGE##*:}"
API_REPO="${API_IMAGE%:*}"
WEB_REPO="${WEB_IMAGE%:*}"
CLUSTER="${KIND_CLUSTER_NAME:-threatsight-p3f}"
TMP="$(mktemp -d /tmp/kind-p3f-XXXX)"

cleanup() {
  kubectl --context "${CTX}" delete ns "${NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "${TMP}"
}
trap cleanup EXIT

echo "== helm lint/template/schema =="
helm lint "${ROOT}/deploy/helm/threatsight"
"${ROOT}/deploy/scripts/helm_template_guard.sh"

if ! kind get clusters | grep -qx "${CLUSTER}"; then
  echo "kind cluster ${CLUSTER} missing; create with kind create cluster --name ${CLUSTER}" >&2
  exit 1
fi

echo "== load images into kind =="
kind load docker-image "${API_IMAGE}" --name "${CLUSTER}"
kind load docker-image "${WEB_IMAGE}" --name "${CLUSTER}"
kubectl --context "${CTX}" create namespace "${NS}"

# Disposable Ed25519 key (never commit)
python3 - <<PY
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key = Ed25519PrivateKey.generate()
Path("${TMP}/signing.pem").write_bytes(
    key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)
PY

echo "== disposable external-style postgres (hostname not 'postgres') =="
# pilot-kubernetes rejects hostname postgres/localhost — use customer-postgres.
kubectl --context "${CTX}" -n "${NS}" create secret generic threatsight-database \
  --from-literal=url='postgresql+psycopg://threatsight:pilot-disp-secret-9f3a@customer-postgres:5432/threatsight'
kubectl --context "${CTX}" -n "${NS}" create secret generic threatsight-oidc \
  --from-literal=client-secret='disposable-oidc-secret'
kubectl --context "${CTX}" -n "${NS}" create secret generic threatsight-radar \
  --from-literal=token='disposable-radar-not-production'
kubectl --context "${CTX}" -n "${NS}" create secret generic threatsight-vulncheck \
  --from-literal=token='disposable-vulncheck-not-production'
kubectl --context "${CTX}" -n "${NS}" create secret generic threatsight-signing-key \
  --from-file=private-key="${TMP}/signing.pem"

kubectl --context "${CTX}" -n "${NS}" apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: customer-postgres
spec:
  replicas: 1
  selector:
    matchLabels: {app: customer-postgres}
  template:
    metadata:
      labels: {app: customer-postgres}
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine
          env:
            - name: POSTGRES_USER
              value: threatsight
            - name: POSTGRES_PASSWORD
              value: pilot-disp-secret-9f3a
            - name: POSTGRES_DB
              value: threatsight
          ports:
            - containerPort: 5432
          readinessProbe:
            exec:
              command: ["pg_isready", "-U", "threatsight"]
            initialDelaySeconds: 3
            periodSeconds: 3
---
apiVersion: v1
kind: Service
metadata:
  name: customer-postgres
spec:
  selector: {app: customer-postgres}
  ports:
    - port: 5432
      targetPort: 5432
EOF

kubectl --context "${CTX}" -n "${NS}" rollout status deploy/customer-postgres --timeout=120s

echo "== disposable keycloak (available; API config uses https placeholders for fail-closed HTTPS rules) =="
kubectl --context "${CTX}" -n "${NS}" apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
spec:
  replicas: 1
  selector:
    matchLabels: {app: keycloak}
  template:
    metadata:
      labels: {app: keycloak}
    spec:
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:26.0
          args: ["start-dev", "--http-port=8080"]
          env:
            - name: KEYCLOAK_ADMIN
              value: admin
            - name: KEYCLOAK_ADMIN_PASSWORD
              value: disposable-admin
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /realms/master
              port: 8080
            initialDelaySeconds: 20
            periodSeconds: 10
            failureThreshold: 30
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
spec:
  selector: {app: keycloak}
  ports:
    - port: 8080
      targetPort: 8080
EOF

kubectl --context "${CTX}" -n "${NS}" rollout status deploy/keycloak --timeout=300s || true

# HTTPS issuer placeholders satisfy fail-closed production config. Live Keycloak is present for optional follow-on login drills.
OIDC_ISS="https://login.example/realms/threatsight"
helm upgrade --install threatsight "${ROOT}/deploy/helm/threatsight" \
  --namespace "${NS}" \
  --set publicOrigin=https://threatsight.example \
  --set image.api.repository="${API_REPO}" \
  --set image.api.tag="${API_TAG}" \
  --set image.web.repository="${WEB_REPO}" \
  --set image.web.tag="${WEB_TAG}" \
  --set config.oidc.issuer="${OIDC_ISS}" \
  --set config.oidc.audience=threatsight-api \
  --set config.oidc.clientId=threatsight \
  --set config.oidc.authorizationEndpoint="${OIDC_ISS}/protocol/openid-connect/auth" \
  --set config.oidc.tokenEndpoint="${OIDC_ISS}/protocol/openid-connect/token" \
  --set config.oidc.jwksUri="${OIDC_ISS}/protocol/openid-connect/certs" \
  --set config.oidc.redirectUri=https://threatsight.example/api/v1/auth/callback \
  --set api.replicas=2 \
  --set web.replicas=2 \
  --set intelWorker.replicas=1 \
  --set evidenceSigner.replicas=1 \
  --wait --timeout 6m

echo "== post-install status =="
kubectl --context "${CTX}" -n "${NS}" get pods,jobs,svc,networkpolicy
kubectl --context "${CTX}" -n "${NS}" wait --for=condition=available deploy/threatsight-api --timeout=180s
kubectl --context "${CTX}" -n "${NS}" wait --for=condition=available deploy/threatsight-web --timeout=120s
kubectl --context "${CTX}" -n "${NS}" scale deploy/threatsight-api --replicas=3
kubectl --context "${CTX}" -n "${NS}" rollout status deploy/threatsight-api --timeout=180s
kubectl --context "${CTX}" -n "${NS}" rollout restart deploy/threatsight-web
kubectl --context "${CTX}" -n "${NS}" rollout status deploy/threatsight-web --timeout=180s
helm upgrade threatsight "${ROOT}/deploy/helm/threatsight" --namespace "${NS}" \
  --reuse-values --set web.replicas=3 --wait --timeout 3m
helm uninstall threatsight --namespace "${NS}"
kubectl --context "${CTX}" delete ns "${NS}" --wait=true
trap - EXIT
rm -rf "${TMP}"
echo "kind_acceptance_ok"
