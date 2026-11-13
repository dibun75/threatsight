from __future__ import annotations

import re

_DOTTED = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_UNORDERABLE = {"junos", "meraki", "cloud", "vendor", "unknown"}


def _parts(value: str) -> tuple[int, int, int] | None:
    match = _DOTTED.fullmatch(value.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def compare_version(scheme: str, observed: str | None, constraint: str | None) -> str:
    """Return applicable, outside, missing, or unknown.

    Only a dotted numeric major.minor.patch constraint is ordered. An exact
    version or an inclusive lower bound and exclusive upper bound are accepted.
    Every other scheme stays unknown.
    """
    if not observed or not str(observed).strip():
        return "missing"
    if scheme in _UNORDERABLE or scheme != "semver":
        return "unknown"
    current = _parts(str(observed))
    if current is None or not constraint:
        return "unknown"
    text = constraint.strip()
    exact = _parts(text)
    if exact is not None:
        return "applicable" if current == exact else "outside"
    bounds = [part.strip() for part in text.split(",")]
    if len(bounds) != 2 or not bounds[0].startswith(">=") or not bounds[1].startswith("<"):
        return "unknown"
    lower = _parts(bounds[0][2:])
    upper = _parts(bounds[1][1:])
    if lower is None or upper is None:
        return "unknown"
    if lower <= current < upper:
        return "applicable"
    return "outside"
