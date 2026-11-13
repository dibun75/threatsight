"""User-facing names for synthetic reference records. Source keys stay stored."""

from __future__ import annotations

NAMES = {
    "synthetic.fixture:device:exact-widget": "ordering-widget",
    "device:exact-widget": "ordering-widget",
    "meraki.dashboard:device:meraki-ap": "privileged-access-gateway",
    "device:meraki-ap": "privileged-access-gateway",
    "junos.device:device:junos-edge:software": "remote-access-vpn-oslo 23.4R1-synth",
    "junos.device:device:junos-edge": "remote-access-vpn-oslo",
    "device:junos-edge": "remote-access-vpn-oslo",
}

MATCHES = {
    "confirmed_identifier_match": "Identifier match",
    "version_supported_candidate": "Version-supported candidate",
    "possible_match": "Possible match",
    "unknown": "Unknown",
    "conflicting": "Conflicting",
    "not_applicable_by_evidence": "Not applicable by evidence",
}


def public_name(value: str | None, fallback: str | None = None) -> str:
    text = (value or "").strip()
    if text in NAMES:
        return NAMES[text]
    for key, label in sorted(NAMES.items(), key=lambda item: len(item[0]), reverse=True):
        if text.endswith(key):
            return label
    shown = (fallback or text or "Synthetic reference").strip()
    if shown.startswith("device:") or "synthetic.fixture:" in shown:
        return "Synthetic reference"
    return shown


def public_match(value: str | None) -> str:
    text = (value or "").strip()
    if text in MATCHES:
        return MATCHES[text]
    if text in MATCHES.values():
        return text
    return "Unknown state"
