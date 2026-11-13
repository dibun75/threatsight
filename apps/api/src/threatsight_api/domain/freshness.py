from __future__ import annotations

from datetime import UTC, datetime, timedelta

from threatsight_api.domain.enums import EvidenceFreshness

FRESHNESS_STATES = [item.value for item in EvidenceFreshness]
DEFAULT_WINDOW_DAYS = 30


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def classify_freshness(
    observed_at: datetime | None,
    *,
    now: datetime | None = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> str:
    if observed_at is None:
        return EvidenceFreshness.UNTESTED.value
    instant = as_utc(observed_at)
    clock = as_utc(now) or datetime.now(UTC)
    if instant is None:
        return EvidenceFreshness.UNTESTED.value
    if clock - instant <= timedelta(days=max(window_days, 0)):
        return EvidenceFreshness.FRESH.value
    return EvidenceFreshness.STALE.value
