from __future__ import annotations

from collections import Counter

from threatsight_api.domain.assurance import assert_assurance_status
from threatsight_api.domain.enums import AssuranceStatus

COVERAGE_KEYS = [status.value for status in AssuranceStatus]


def count_coverage(values: list[str], allowed: list[str] | None = None) -> dict[str, int]:
    keys = allowed or COVERAGE_KEYS
    tallies = Counter(values)
    return {key: int(tallies.get(key, 0)) for key in keys}


def coverage_from_control_statuses(statuses: list[str]) -> str:
    cleaned: list[str] = []
    for raw in statuses:
        cleaned.append(assert_assurance_status(raw).value)
    if not cleaned:
        return AssuranceStatus.EVIDENCE_REQUIRED.value
    unique = set(cleaned)
    if unique == {AssuranceStatus.NOT_APPLICABLE.value}:
        return AssuranceStatus.NOT_APPLICABLE.value
    if AssuranceStatus.GAP_DETECTED.value in unique:
        return AssuranceStatus.GAP_DETECTED.value
    if AssuranceStatus.HUMAN_REVIEW_REQUIRED.value in unique:
        return AssuranceStatus.HUMAN_REVIEW_REQUIRED.value
    if unique == {AssuranceStatus.VALIDATED.value}:
        return AssuranceStatus.VALIDATED.value
    if AssuranceStatus.VALIDATED.value in unique or AssuranceStatus.PARTIALLY_VALIDATED.value in unique:
        return AssuranceStatus.PARTIALLY_VALIDATED.value
    return AssuranceStatus.EVIDENCE_REQUIRED.value
