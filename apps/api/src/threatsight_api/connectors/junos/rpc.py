"""Versioned read-only Junos RPC allowlist. Payloads are fixed templates."""

from __future__ import annotations

from threatsight_api.connectors.junos.bounds import CONTRACT, CollectionFailure

NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
OPERATIONS = (
    "hello",
    "get-system-information",
    "get-config-zones",
    "get-config-routing",
    "get-interface-information",
    "get-config-interfaces",
    "get-config-policies",
    "get-route-information",
    "get-config-vpn",
    "get-config-services",
)
ALLOWED = frozenset(OPERATIONS)
PROHIBITED = (
    "edit-config",
    "copy-config",
    "delete-config",
    "lock",
    "unlock",
    "commit",
    "commit-configuration",
    "confirmed-commit",
    "validate",
    "discard-changes",
    "kill-session",
    "close-session",
    "load-configuration",
    "request-reboot",
    "request-package-add",
    "request-package-delete",
    "clear-interfaces",
    "command",
    "op",
    "get-config",
)
_BANNED_MARKERS = (
    b"<edit-config",
    b"<copy-config",
    b"<delete-config",
    b"<lock",
    b"<unlock",
    b"<commit",
    b"<validate",
    b"<discard-changes",
    b"<kill-session",
    b"<load-configuration",
    b"<request-",
    b"<clear-",
    b"<command",
    b"<op>",
    b"<cli",
    b"pre-shared-key",
    b"private-key",
)


def _rpc(body: str) -> bytes:
    return f'<rpc xmlns="{NS}">{body}</rpc>'.encode()


REQUESTS = {
    "hello": (
        f'<hello xmlns="{NS}"><capabilities>'
        "<capability>urn:ietf:params:netconf:base:1.0</capability>"
        "<capability>urn:ietf:params:netconf:base:1.1</capability>"
        "</capabilities></hello>"
    ).encode(),
    "get-system-information": _rpc("<get-system-information/>"),
    "get-interface-information": _rpc("<get-interface-information><terse/></get-interface-information>"),
    "get-config-interfaces": _rpc(
        "<get-config><source><running/></source><filter type=\"subtree\">"
        "<configuration><interfaces/></configuration></filter></get-config>"
    ),
    "get-config-zones": _rpc(
        "<get-config><source><running/></source><filter type=\"subtree\">"
        "<configuration><security><zones/></security></configuration></filter></get-config>"
    ),
    "get-config-policies": _rpc(
        "<get-config><source><running/></source><filter type=\"subtree\">"
        "<configuration><security><policies/></security></configuration></filter></get-config>"
    ),
    "get-config-routing": _rpc(
        "<get-config><source><running/></source><filter type=\"subtree\">"
        "<configuration><routing-instances/></configuration></filter></get-config>"
    ),
    "get-route-information": _rpc("<get-route-information><table>inet.0</table></get-route-information>"),
    "get-config-vpn": _rpc(
        "<get-config><source><running/></source><filter type=\"subtree\">"
        "<configuration><security><ike><gateway/></ike><ipsec><vpn/></ipsec></security>"
        "</configuration></filter></get-config>"
    ),
    "get-config-services": _rpc(
        "<get-config><source><running/></source><filter type=\"subtree\">"
        "<configuration><system><services/></system></configuration></filter></get-config>"
    ),
}


def assert_allowed(operation: str) -> None:
    if (
        not isinstance(operation, str)
        or operation not in ALLOWED
        or operation in PROHIBITED
        or operation.startswith(("clear-", "request-", "load-", "commit"))
    ):
        raise CollectionFailure("rpc_rejected")


def render(operation: str) -> bytes:
    assert_allowed(operation)
    body = REQUESTS[operation]
    if any(marker in body for marker in _BANNED_MARKERS):
        raise CollectionFailure("rpc_rejected")
    return body


def contract() -> str:
    return CONTRACT
