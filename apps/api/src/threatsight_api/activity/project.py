"""Observed-activity projection. It does not collect from an external feed."""

from __future__ import annotations

WINDOWS = ("1h", "24h", "7d", "30d")
LAYERS = ("all", "scanning", "mitigated")
DIRECTIONS = ("target", "origin", "pair")

# Fixed synthetic counts. They are not observations from a live sensor.
_FIXTURE = (
    {"code": "US", "name": "United States", "role": "target", "layer": "scanning", "magnitude": 80, "lon": -98.0, "lat": 39.0},
    {"code": "DE", "name": "Germany", "role": "origin", "layer": "scanning", "magnitude": 24, "lon": 10.0, "lat": 51.0},
    {"code": "SG", "name": "Singapore", "role": "target", "layer": "mitigated", "magnitude": 12, "lon": 103.8, "lat": 1.3},
)
_PAIR = {
    "origin": "DE",
    "target": "US",
    "magnitude": 24,
    "meaning": "The synthetic source explicitly pairs these countries. This is not attacker attribution.",
}


def activity_view(*, window: str, layer: str, direction: str) -> dict:
    if window not in WINDOWS or layer not in LAYERS or direction not in DIRECTIONS:
        raise ValueError("unsupported activity query")
    available = window == "24h"
    rows = [dict(item) for item in _FIXTURE if available and (layer == "all" or item["layer"] == layer)]
    if direction in {"origin", "target"}:
        rows = [item for item in rows if item["role"] == direction]
    arcs = [_PAIR] if available and direction == "pair" and layer in {"all", "scanning"} else []
    return {
        "source": "threatsight.synthetic-activity",
        "contract_version": "1",
        "maturity": "fixture_tested",
        "live": False,
        "license": "not_approved_for_live_collection",
        "label": "Synthetic demonstration — not live attack telemetry.",
        "measurement": "Synthetic counts for a demonstration window. They are not mitigated requests from a customer or a commercial feed.",
        "unit": "synthetic events",
        "window": window,
        "direction": direction,
        "layer": layer,
        "freshness": "fixture" if available else "unavailable",
        "collected_at": None,
        "locations": rows[:20],
        "arcs": arcs[:5],
        "limitations": [
            "Advisory geography is not observed attack activity or attacker attribution.",
            "No commercial attack feed is enabled.",
            "The demonstration only populates a 24 hour window.",
            "Country names in this response are synthetic locations, not a customer footprint.",
        ],
        "does_not_mean": "These figures are not live detection, attribution, or proof that a control failed.",
    }
