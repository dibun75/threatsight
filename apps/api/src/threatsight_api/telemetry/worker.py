"""Radar collection runs only inside the intelligence worker."""

from __future__ import annotations

import os

from sqlalchemy import text

from threatsight_api.telemetry.client import fetch_dataset, load_token
from threatsight_api.telemetry.contract import RadarError
from threatsight_api.telemetry.publish import collect_window, publish, record_failure, record_state

INTERVAL_MINUTES = 20
LOCK = 213011


def maybe_collect(db, *, enabled: bool | None = None, fetch=fetch_dataset, running: bool = True) -> dict:
    if enabled is None:
        enabled = os.environ.get("THREATSIGHT_RADAR_ENABLED", "").lower() in {"1", "true", "yes"}
    if not enabled:
        _record_once(db, "disabled")
        return {"state": "disabled"}
    if os.environ.get("THREATSIGHT_INTEL_KILL_SWITCH", "").lower() in {"1", "true", "yes"} or os.environ.get("THREATSIGHT_KILL_SWITCH", "").lower() in {"1", "true", "yes"}:
        _record_once(db, "disabled")
        return {"state": "disabled"}
    locked = db.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK}).scalar()
    if not locked:
        return {"state": "collecting"}
    try:
        recent = db.execute(
            text(
                """
                SELECT started_at FROM telemetry_runs
                 WHERE source = 'cloudflare_radar' AND status = 'succeeded'
                   AND started_at > now() - make_interval(mins => :minutes)
                 ORDER BY started_at DESC LIMIT 1
                """
            ),
            {"minutes": INTERVAL_MINUTES},
        ).scalar()
        if recent is not None:
            return {"state": "current"}
        try:
            token = load_token(os.environ.get("THREATSIGHT_RADAR_TOKEN_FILE", ""))
        except RadarError as exc:
            if exc.code == "token_path_rejected":
                _record_once(db, "externally_gated")
                return {"state": "externally_gated"}
            record_failure(db, window="24h", code=exc.code, has_current=_has_current(db))
            return {"state": "failed_no_snapshot"}
        if not running:
            record_failure(db, window="24h", code="cancelled", has_current=_has_current(db))
            return {"state": "cancelled"}
        for window in ("24h", "7d"):
            if not running:
                record_failure(db, window=window, code="cancelled", has_current=_has_current(db))
                return {"state": "cancelled"}

            def _fetch(dataset: str, item: str, location: str | None = None, _token: str = token):
                return fetch(dataset, item, token=_token, location=location)

            try:
                collected = collect_window(window, _fetch)
            except RadarError as exc:
                record_failure(db, window=window, code=exc.code, has_current=_has_current(db))
                return {"state": "failed_using_last_known_good" if _has_current(db) else "failed_no_snapshot"}
            publish(db, collected, window=window)
        return {"state": "current"}
    finally:
        db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK})


def _record_once(db, status: str) -> None:
    recent = db.execute(
        text(
            """
            SELECT 1 FROM telemetry_runs
             WHERE source = 'cloudflare_radar' AND status = :status
               AND started_at > now() - interval '15 minutes'
             LIMIT 1
            """
        ),
        {"status": status},
    ).scalar()
    if recent is None:
        record_state(db, status)


def _has_current(db) -> bool:
    return db.execute(text("SELECT 1 FROM telemetry_snapshots WHERE source = 'cloudflare_radar' AND is_current LIMIT 1")).scalar() is not None
