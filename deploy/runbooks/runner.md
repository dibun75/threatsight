# Customer runner guide

The observation-sensor privacy and authorization boundary is defined in [the customer-resident sensor contract](../../docs/reference/customer-resident-sensor.md) and ADR 0043.

- Deployed **separately** from control-plane pods (Compose profile or separate chart later).
- Outbound-only to the approved HTTPS control-plane origin.
- Credential from `THREATSIGHT_RUNNER_CREDENTIAL_FILE` — never committed.
- No inbound host port in reference packaging.
- Version compatibility: runner should track the control-plane minor series used by the pilot.
