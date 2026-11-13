"""RFC 8288 Link parsing for Meraki pagination.

Cisco documents the same link relations under RFC 5988. Only ``rel=next`` is
followed, and only after the target passes the origin and path checks.
"""

from __future__ import annotations

import re

from threatsight_api.connectors.meraki.bounds import CollectionFailure, approved_url

_LINK = re.compile(r"<([^>]*)>\s*;\s*([^,]*)")


def _is_next(params: str) -> bool:
    for part in params.split(";"):
        item = part.strip()
        if not item.lower().startswith("rel="):
            continue
        raw = item.split("=", 1)[1].strip().strip('"').strip("'")
        return "next" in {value.strip().lower() for value in raw.split()}
    return False


def next_link(header: str | None, *, origin: str, path: str) -> str | None:
    if not header:
        return None
    if len(header) > 4000 or any(ord(ch) < 32 for ch in header):
        raise CollectionFailure("destination_refused")
    found: list[str] = []
    for match in _LINK.finditer(header):
        if _is_next(match.group(2)):
            found.append(match.group(1).strip())
    if not found:
        return None
    if len(found) != 1:
        raise CollectionFailure("destination_refused")
    return approved_url(found[0], origin=origin, path=path)
