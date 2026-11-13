"""DShield top-port parser. Live collection stays off until terms are accepted for this product."""

from __future__ import annotations

import json

ATTRIBUTION = "SANS Technology Institute, Internet Storm Center"
LABEL = "Contributed firewall and honeypot observations"


class DShieldError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_top_ports(payload: bytes) -> list[dict]:
    if len(payload) > 500_000:
        raise DShieldError("response_too_large")
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise DShieldError("schema") from exc
    rows = document if isinstance(document, list) else document.get("data") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        raise DShieldError("schema")
    parsed = []
    for item in rows[:20]:
        if not isinstance(item, dict):
            raise DShieldError("schema")
        if any(key in item for key in ("user", "password", "username", "ip", "source_ip")):
            continue
        port = item.get("targetport") or item.get("port")
        try:
            number = int(port)
        except (TypeError, ValueError):
            continue
        if not 0 < number < 65536:
            continue
        parsed.append({"port": number, "records": item.get("records")})
    return parsed


def status() -> dict:
    return {
        "source": "dshield",
        "label": LABEL,
        "enabled": False,
        "state": "terms_gated",
        "attribution": ATTRIBUTION,
        "reason": "Commercial redistribution of the feed is not accepted for this product yet. No DShield rows are stored.",
    }
