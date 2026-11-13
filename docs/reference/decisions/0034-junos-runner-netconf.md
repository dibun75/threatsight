# ADR 0034: Junos NETCONF stays on the customer runner

Status: Accepted

Date: 2026-10-30

## Context

P2-10 needs a read-only Junos inventory for the synthetic Nordic Retail scenario. NETCONF over SSH is the Juniper management protocol. The API and the customer runner currently share one image, and that image is the deployed Phase 1 API. Rebuilding it, or importing an SSH stack into the API process, would put device-facing code on the control plane.

`defusedxml==0.7.1` is already a direct dependency and is used for untrusted XML. `cryptography==46.0.3` is already pinned. No NETCONF or SSH client is installed.

## Decision

The Junos reference adapter parses fixture replies with the existing `defusedxml` pin. It does not add `ncclient`, `paramiko`, `lxml`, or another SSH library.

Live mode validates the workspace target, port, pinned host key, algorithm, and runner-local secret reference, then fails closed with `live_transport_unavailable`. It does not open a socket. A runner-only NETCONF extra can be considered later, when a design partner authorizes a device and an image rebuild is explicitly approved. That extra must not be imported by the central API.

Junos-specific RPC names sit behind adapter contract `junos-rpc-v1`. Standard NETCONF framing and the read-only operation classes stay the protocol boundary.

## Consequences

- Fixture tests do not need a device, a new package, or an image rebuild.
- The public API image remains `threatsight-api:23f8def`.
- Nothing in this build is `live_verified`.
- The collector never assigns `live_verified`. A later authorized run still needs a reviewed evidence record before that maturity is used.
