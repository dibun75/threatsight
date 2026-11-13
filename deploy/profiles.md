# Deployment profiles

## reference

- **Audience:** product development and public reference demo.
- **Auth:** development / local / OIDC / public_demo as configured on the host.
- **Postgres:** bundled Compose service; may publish localhost ports.
- **Ingress:** optional Cloudflare Tunnel via `docker-compose.tunnel.yml` (external to product).
- **Data:** synthetic reference journeys permitted.
- **Claims:** none beyond “reference installation.”

## pilot-compose

- **Audience:** customer-controlled single VM/server design partner.
- **Auth:** generic OIDC **required by default**; local auth only as documented break-glass.
- **Postgres:** unpublished port by default; optional external URL.
- **Secrets:** Docker secret files / bind-mounted files (mode `0400` where detectable).
- **Ingress:** customer TLS reverse proxy; product binds localhost or internal network only for admin surfaces.
- **Data:** synthetic loaders **disabled** unless explicitly enabled.
- **Claims:** pilot packaging only—not HA, DR, or production certification.

## pilot-kubernetes

- **Audience:** customer-managed Kubernetes.
- **Auth:** generic OIDC required.
- **Postgres:** **external required** (no bundled production database claim).
- **Secrets:** Kubernetes Secret references / CSI; never in values output.
- **Ingress:** customer-provided; chart ingress **disabled by default**.
- **Workers:** intelligence and signer may scale only with existing DB locks/leases.
- **Claims:** none for cluster HA; PostgreSQL availability is the customer’s responsibility.
