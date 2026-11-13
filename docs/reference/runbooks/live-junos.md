# Juniper Junos live validation

The current collector does not open a NETCONF session. Live mode returns `live_transport_unavailable` after the policy checks. That result is not a successful collection and must not be marked `live_verified`.

## Decision required before any live attempt

1. Select a maintained SSH/NETCONF library.
2. Security-review it.
3. Pin and audit it.
4. Keep it in the runner image only. The central API must not import it.
5. Test strict host-key pinning. Trust-on-first-use is not acceptable.
6. Validate the supported Junos devices and releases with the partner.
7. Confirm a read-only login class.
8. Confirm the prohibited operational commands stay rejected.
9. Obtain customer authorization for one device and one window.

Do not add a transport only to close this checklist.

## When that decision is made

- Connector key `junos.device`.
- Record runner and control-plane versions.
- One target, one port, a pinned `SHA256:` host key, and an accepted algorithm.
- Secret reference for the read-only account. The private key stays on the runner.
- Expected records are the normalized interface, zone, and address-book fields. Excluded: raw XML, descriptions, and error text.
- Bounds remain the existing byte, time, and retry limits. Stop on kill switch, host-key mismatch, or any write RPC.
- Rollback revokes the runner and disables the login class.

Maturity still requires the ten conditions in [live-azure.md](./live-azure.md), including customer acceptance. A completed TCP handshake would not be enough even after a library is added.
