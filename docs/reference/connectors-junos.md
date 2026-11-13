# Juniper Junos NETCONF connector

Status: `fixture_tested` on 2026-10-30. This is not `live_verified`.

The adapter key is `junos.device`. It runs only on the existing customer-resident runner, secret-reference, and durable-job path. The central API does not open NETCONF. Device credentials and SSH private keys stay on the runner. Stored results are normalized records, not configuration dumps or RPC transcripts.

Contract id: `junos-rpc-v1`. Decision: [ADR 0034](./decisions/0034-junos-runner-netconf.md).

Junos releases, device families, YANG modules, RPC reply shapes, login-class behavior, and host-key algorithms need design-partner validation before any live claim.

## Official contracts

Reviewed 2026-10-30. No live device was available to confirm a specific Junos release.

| Topic | Source | What this adapter uses |
| --- | --- | --- |
| NETCONF | [RFC 6241](https://www.rfc-editor.org/rfc/rfc6241) | Read operations only. No edit, copy, delete, lock, unlock, commit, or validate. |
| NETCONF over SSH | [RFC 6242](https://www.rfc-editor.org/rfc/rfc6242) | SSHv2 subsystem `netconf`. Default TCP port 830. Other ports only when an administrator sets `port_override`. |
| Port assignment | [IANA service name `netconf`](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=830) | 830 is the only default. |
| Junos NETCONF over SSH | [Establish an SSH connection for a NETCONF session](https://www.juniper.net/documentation/us/en/software/junos/netconf/topics/topic-map/netconf-ssh-connection.html) | The device must enable NETCONF over SSH. Port 22 is not used unless an administrator explicitly overrides the port. The adapter never requests a shell. |
| Junos session capabilities | [NETCONF sessions](https://www.juniper.net/documentation/us/en/software/junos/netconf/topics/topic-map/netconf-sessions.html) | Requires `urn:ietf:params:netconf:base:1.0` or `base:1.1`, and `http://xml.juniper.net/netconf/junos/1.0`. Advertised URL, file, commit, and validate capabilities are ignored. |
| Operational RPC | [Request operational information](https://www.juniper.net/documentation/us/en/software/junos/junos-xml-protocol/topics/task/junos-xml-protocol-requesting-operational-information.html) | Fixed `get-system-information`, terse `get-interface-information`, and table-scoped `get-route-information`. |
| Configuration RPC | [Request configuration data](https://www.juniper.net/documentation/us/en/software/junos/junos-xml-protocol/topics/topic-map/junos-xml-protocol-request-configuration-information.html) | `get-config` with source `running` and a fixed subtree. Candidate configuration is not read. `load-configuration` is prohibited. |
| Account | [Junos user accounts](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-user-accounts.html) | Assumption: a dedicated user in the predefined `read-only` login class, with an SSH public key and no shell. A design partner must confirm that class cannot issue operational clear or request commands. The adapter also refuses those RPCs locally. |

The third-party NETCONF Central copy of `junos-rpc-system` was not used as the contract.

## Permission and setup

1. Register a customer-resident runner in the workspace. The connector cannot be saved without one.
2. Create a secret reference. Live mode requires it. The locator is redacted on ordinary API responses and is returned only to the owning runner at claim.
3. On the runner host, inject `THREATSIGHT_JUNOS_CREDENTIALS` as a JSON map from that locator to `{"username","private_key"}`. Do not commit the map, the key, or a passphrase.
4. Fixture mode takes a workspace `device_id` and a sanitized fixture name. It has no target host.
5. Live mode takes one explicit `target_host`, port `830` unless `port_override` is true, `host_key_algorithm` of `ssh-ed25519`, `rsa-sha2-256`, or `rsa-sha2-512`, and either a `SHA256:` host-key fingerprint or a customer-managed `known_hosts_reference` locator. There is no trust-on-first-use path. A filesystem path is rejected. This build does not open a known-hosts file.
6. Leave `THREATSIGHT_JUNOS_LIVE` unset or false. The collector does not assign `live_verified`.

Hostname collected from the device is an informational label. It is not the connection authority. The connection target is only the configured `target_host`.

## Read-only RPC allowlist

Internal operations, in order:

1. `hello`
2. `get-system-information`
3. `get-config-zones`
4. `get-config-routing`
5. `get-interface-information`
6. `get-config-interfaces`
7. `get-config-policies`
8. `get-route-information` for table `inet.0`, then capped at 8 destinations
9. `get-config-vpn`
10. `get-config-services`

The request bodies are fixed templates. API clients cannot submit an RPC, XML body, XPath, or subtree filter. Job input must be empty. A non-empty Junos job input is rejected and audited as `rpc_rejected` without storing the submitted body.

These operations fail closed and are not sent: `edit-config`, `copy-config`, `delete-config`, `lock`, `unlock`, `commit`, `commit-configuration`, `confirmed-commit`, `validate`, `discard-changes`, `kill-session`, `close-session`, `load-configuration`, `request-reboot`, `request-package-add`, `request-package-delete`, `clear-interfaces`, `command`, `op`, a bare `get-config`, and any `clear-`, `request-`, `load-`, or `commit` name. Execution of a prohibited name raises `rpc_rejected` before a transport send.

## Retained fields

Every record stores `kind`, `external_id`, `collected_at`, `truth_state`, bounded attributes, provenance (`contract`, `operation`, `mode`), and limitations. Provenance does not include the host, username, or key.

| Kind | Retained attributes | Purpose |
| --- | --- | --- |
| `capability` | `base_1_0`, `base_1_1`, `junos_1_0` | Prove the negotiated read contract. Raw capability URLs are not stored. |
| `device` | workspace `device_id`, `model`, `chassis_id`, `junos_version`, `informational_hostname` | Inventory identity. The hostname is labelled non-authoritative. |
| `interface` | `name`, parent, admin/oper status, `zone`, routing instance, `management` | Interface and zone inventory. `management` is true only when the assigned zone's host-inbound configuration includes `ssh` or `netconf`. The name `fxp0` is not authority. |
| `interface_address` | host address and prefix length, separately | Interface addressing. Host bits are retained as `prefix_has_host_bits` and are not rewritten into a network. |
| `security_zone` | name, member interfaces, host-inbound services from `ssh`, `netconf`, `ping`, `https`, `traceroute` | Zone membership for later exposure analysis. |
| `routing_instance` | name, type, member interfaces | Routing-instance association. |
| `route` | destination prefix, next hop, interface, protocol, table `inet.0` | Bounded path metadata. At most 8 prefixes, chosen deterministically. |
| `security_policy` | name, order, zones, address and application references, action `allow` or `deny`, enabled, session-init logging | Policy metadata. Action comes from `permit` or `deny`, not from the policy name. |
| `vpn_gateway` | gateway name, tunnel name, peer address, external interface, bind interface, `UP`/`DOWN` when present | Topology only. |
| `management_service` | service name, allowing zones, `reachability=not_observed` | Configured management services. Configuration is not treated as packet reachability. |
| `collection_status` | page count, partial flag, limitation codes | Collection outcome. |

Truth states used on records are `observed`, `configured`, `partial`, `stale`, `unknown`, `conflicting`, and `unsupported`. Envelope maturity stays `fixture_tested` for fixture mode. Live mode, if it ever completes under a future transport, stays `experimental` until a reviewed evidence record says otherwise.

## Deliberately excluded

The adapter does not retain complete configurations, raw XML, NETCONF transcripts, SSH banners, password hashes, encrypted secrets, private or pre-shared keys, SNMP communities, RADIUS or TACACS secrets, certificates, certificate private keys, descriptions, comments, address-book entries that are not referenced by a collected policy, packet or session history, or personal information. Secret-tagged elements are cleared before normalization. If a retained value still contains markup or a private-key banner, the collection fails closed with `minimization_rejected`.

A subtree filter can still cause a device to return a secret child. The fixture includes a pre-shared key, a password hash, an SNMP community, a RADIUS secret, and a certificate to prove those values are absent from the stored envelope.

## SSH and XML controls

- One configured target per connector instance, bound to the job tenant and workspace. A mismatched runner stops before RPC.
- Default port 830. Another port requires `port_override`.
- Host-key comparison is exact and timing-safe. A missing pin fails with `host_key_required`. A mismatch fails with `host_key_mismatch`. The error does not include the key, host, or username.
- Accepted host-key algorithms are only `ssh-ed25519`, `rsa-sha2-256`, and `rsa-sha2-512`.
- IP literals are used as given. Names are resolved twice and must return the same single address. Link-local, loopback, unspecified, multicast, and metadata names are refused. The default resolver refuses without calling the system resolver.
- Proxy environment variables are ignored. NETCONF has no redirect or proxy discovery step.
- Connect, read, DNS, and session budgets are 10s, 20s, 2s, and 60s. Those timers are policy constants in this build because no socket is opened.
- Connection timeout retries at most three attempts, with delays of 0.25s and 0.5s. Authentication failure is not retried. Job-level retry is not enabled for connection failure, so a timeout cannot amplify through the queue.
- XML parsing uses `defusedxml`. DTD, entities, XInclude, and external references are rejected. Documents are limited to 256 KiB, depth 16, 2,000 nodes, and 200 characters of text. Descriptions and error text are dropped. Parse errors do not log the document.
- Interface names, zones, addresses, and prefixes use explicit parsers. Invalid or host-bit route prefixes are dropped rather than masked.
- Repeated fixture collection is sorted and hashed. The same input produces the same content hash.
- Failure details that contain markup or a private-key banner are stored as the error code only.
- The package does not invoke a shell, write a temporary file, or import an SSH client.

## Live validation

Disabled by default. Ordinary tests do not set `THREATSIGHT_JUNOS_LIVE` and do not open a socket. Do not mark a result `live_verified` from this procedure until every item below is true and the evidence has been reviewed.

1. Set `THREATSIGHT_JUNOS_LIVE=true` only on the customer-resident runner process. Do not enable it on the public API.
2. Use a runner registered to the authorized tenant and workspace.
3. Configure one explicit target, port, pinned `SHA256:` host key, and an accepted algorithm. Do not use trust-on-first-use.
4. Resolve the secret reference to a read-only Junos account. Keep the private key on the runner.
5. Record the authorization window, the device, and the reviewer before the run.
6. Confirm the global kill switch is armed and can be turned on during the run.
7. Collect only the allow-listed operations above.
8. Keep the evidence redacted: no key, transcript, or raw XML.
9. Review the envelope before anyone changes maturity. This collector will still report `experimental` for a future live success. `live_verified` is a separate reviewed decision.
10. Unset the flag when the window ends.

This build returns `live_transport_unavailable` after the policy checks because no NETCONF client is linked. That outcome is not a successful live collection.

## Security review

| Threat | Control in this build |
| --- | --- |
| Control plane dials a private device | API routes do not call the session opener. Live dispatch validates policy and then refuses. Tests fail if a socket is created. |
| SSRF or arbitrary private targeting | The target is one configured host. Metadata, loopback, link-local, and unspecified addresses are refused. Fixture mode has no target host. |
| DNS rebinding | A name is resolved twice and must stay one address. The default resolver does not query the network. |
| Host-key bypass | Missing and mismatched pins fail closed. No trust-on-first-use flag exists. |
| Downgraded SSH algorithms | Only three modern host-key algorithms are accepted. |
| Command or RPC injection | Clients cannot submit RPC, XML, XPath, or filters. Templates are constants. A shell is not invoked. |
| NETCONF writes | The prohibited operation list fails closed before send, at enqueue, and in the renderer. |
| XML parser attacks | `defusedxml` plus a pre-check for DTD, entities, and XInclude. Hostile fixtures are rejected without echoing the document. |
| Response-size denial of service | Byte, depth, node, text, route, page, and session limits. Oversized input fails before the tree is built. |
| Reconnect amplification | Three in-session attempts with sub-second delay. Connection failure is not a queue-level retry. |
| Credential or configuration leakage | The private key is validated and discarded. Envelopes, errors, and audits omit raw XML and secret values. Locators are redacted on ordinary responses. |
| Malicious identifiers or descriptions | Labels must match explicit patterns. Descriptions are dropped. Control characters fail closed. |
| Tenant confusion | Runner tenant and workspace are compared before any RPC. A secret reference from another workspace is not attached. |
| Cancellation and lease races | Cancellation and the kill switch finish a partial fixture envelope. Lease loss stops without completing, so another worker can reclaim. |
| Raw-response persistence | Normalized records only. Secret tags are stripped. A minimization failure aborts storage. |
| Unsafe temporary files | The adapter does not create temporary files. |

## Verification

Reviewed 2026-10-30. Focused adapter tests and the API registration test passed. The isolated API suite passed 247 tests and skipped 1. It used a disposable `threatsight_test_` database and dropped it. The preserved database stayed at revision `0013_connector_execution` with 2,182 threat events, 2,182 relevance rows, 41 clusters, 9 sources, 1 business service, 1 radar triage row, 1 readiness link, 32 AI systems, and 33 controls. No `threatsight_test_` database remained.

No Python dependency was added. `pip-audit` and mypy are not installed, and no image was rebuilt, so no new dependency audit or image scan was run. Ruff passed on the adapter, registry, dispatch, and tests. The public API image remained `threatsight-api:23f8def` and health remained milestone M15.

P2-11 records Junos fixture relationships in the exposure graph. Those relationships are not exposure findings. P2-12 path candidates and P2-13 correlation matches do not change that. A Junos train this comparator cannot order stays unknown.
