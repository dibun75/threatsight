from __future__ import annotations

import ipaddress
import socket
import urllib.request
from urllib.parse import urlsplit


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ValueError("endpoint redirected")


def origin_of(value: str) -> str | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def endpoint_problem(value: str) -> str | None:
    parsed = urlsplit(value.strip())
    if parsed.username or parsed.password or parsed.fragment:
        return "must not include credentials or a fragment"
    if parsed.scheme != "https" or not parsed.hostname:
        return "must use HTTPS"
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
        return "must use a public address"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not address.is_global:
        return "must use a public address"
    return None


def assert_public_destination(value: str, *, production: bool) -> None:
    if not production:
        parsed = urlsplit(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.fragment:
            raise ValueError("invalid endpoint")
        return
    problem = endpoint_problem(value)
    if problem:
        raise ValueError(problem)
    parsed = urlsplit(value.strip())
    port = parsed.port or 443
    try:
        answers = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("endpoint host did not resolve") from exc
    if not answers:
        raise ValueError("endpoint host did not resolve")
    for answer in answers:
        address = ipaddress.ip_address(str(answer[4][0]).split("%", 1)[0])
        if not address.is_global:
            raise ValueError("endpoint host resolves to a non-public address")


def open_unredirected(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    method: str | None = None,
    production: bool = False,
):
    assert_public_destination(url, production=production)
    opener = urllib.request.build_opener(_RejectRedirect)
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    return opener.open(request, timeout=5)
