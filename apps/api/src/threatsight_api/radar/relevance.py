from __future__ import annotations

from threatsight_api.radar.contracts import RelevanceResult


def _matches(profile_values: list[str], event_values: list[str]) -> list[str]:
    event_by_key = {value.casefold(): value for value in event_values}
    return sorted(
        (event_by_key[value.casefold()] for value in profile_values if value.casefold() in event_by_key),
        key=str.casefold,
    )


def score_relevance(profile, event, epss_scores: list[float] | None = None) -> RelevanceResult:
    weights = {
        "countries": 25,
        "sectors": 20,
        "vendors": 20,
        "products": 20,
        "technologies": 15,
    }
    matches: dict[str, list[str]] = {}
    reasons: list[str] = []
    score = 0
    for field, weight in weights.items():
        found = _matches(list(getattr(profile, field) or []), list(getattr(event, field) or []))
        if found:
            matches[field] = found
            score += weight
            reasons.append(f"{field[:-1].replace('_', ' ')} match: {', '.join(found)}")

    if getattr(event, "exploitation_status", "unknown") == "known_exploited":
        score += 20
        reasons.append("CISA confirms active exploitation")

    maximum_epss = max(epss_scores or [0.0])
    if maximum_epss >= 0.5:
        score += 15
        reasons.append(f"EPSS exploitation probability is high ({maximum_epss:.1%})")
    elif maximum_epss >= 0.1:
        score += 10
        reasons.append(f"EPSS exploitation probability is elevated ({maximum_epss:.1%})")

    score = min(score, 100)
    if score >= 70:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "none"
    if not reasons:
        reasons.append("No organization-profile match is currently known")
    return RelevanceResult(score=score, level=level, reasons=reasons, matches=matches)
