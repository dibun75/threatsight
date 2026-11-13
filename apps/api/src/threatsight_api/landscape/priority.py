from __future__ import annotations


def priority_reason(
    *,
    version_result: str,
    kev: bool,
    epss: float | None,
    vendor_severity: str | None,
    cvss: float | None,
    conflict: bool,
) -> tuple[int, str]:
    """Lower rank is shown first. The reason names the policy step."""
    applicable = version_result == "applicable"
    critical = (vendor_severity or "").lower() == "critical" or (cvss is not None and cvss >= 9.0)
    if applicable and kev:
        return 1, "Applicable product version and CISA KEV inclusion."
    if applicable and epss is not None and epss >= 0.7:
        return 2, "Applicable product version and EPSS at or above 0.7."
    if applicable and critical:
        return 3, "Applicable product version and critical vendor or CVSS severity."
    if version_result == "missing":
        return 4, "Product match with no comparable version."
    if conflict or version_result == "unknown":
        return 5, "Unresolved or conflicting evidence."
    return 6, "No priority rule matched. Raw facts remain available."
