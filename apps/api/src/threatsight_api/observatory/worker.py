"""DShield collection runs only inside the outbound intelligence worker."""

from __future__ import annotations

import os

from sqlalchemy import text

from threatsight_api.observatory.client import fetch_dataset
from threatsight_api.observatory.contract import ObservatoryError, parse_threat_intel, parse_top_ips, parse_top_ports
from threatsight_api.observatory.publish import publish, record_state

INTERVAL_MINUTES = 60
# After a failed pull, wait before retrying instead of re-downloading the feeds every worker cycle.
FAILURE_BACKOFF_MINUTES = 15
LOCK = 213012


def maybe_collect(db, *, enabled: bool | None = None, fetch=fetch_dataset) -> dict:
    if enabled is None:
        enabled = os.environ.get("THREATSIGHT_DSHIELD_ENABLED", "").lower() in {"1", "true", "yes"}
    if not enabled or os.environ.get("THREATSIGHT_INTEL_KILL_SWITCH", "").lower() in {"1", "true", "yes"}:
        _record_once(db, "disabled")
        return {"state": "disabled"}
    locked = db.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK}).scalar()
    if not locked:
        return {"state": "collecting"}
    try:
        recent = db.execute(
            text(
                """
                SELECT 1 FROM observatory_runs
                WHERE source = 'dshield' AND status = 'succeeded'
                  AND started_at > now() - make_interval(mins => :minutes)
                LIMIT 1
                """
            ),
            {"minutes": INTERVAL_MINUTES},
        ).scalar()
        if recent:
            return {"state": "current"}
        failed = db.execute(
            text(
                """
                SELECT status FROM observatory_runs
                WHERE source = 'dshield' AND status IN ('failed_using_last_known_good', 'failed_no_snapshot')
                  AND started_at > now() - make_interval(mins => :minutes)
                ORDER BY started_at DESC LIMIT 1
                """
            ),
            {"minutes": FAILURE_BACKOFF_MINUTES},
        ).scalar()
        if failed:
            return {"state": failed}
        try:
            rows = parse_top_ips(fetch("top_ips"))
            rows.extend(parse_top_ports(fetch("top_ports")))
            rows.extend(parse_threat_intel(fetch("threat_intel")))
            if not rows:
                raise ObservatoryError("empty_result")
            publish(db, rows)
            return {"state": "current", "count": len(rows)}
        except ObservatoryError as exc:
            has_current = db.execute(text("SELECT 1 FROM observatory_runs WHERE source = 'dshield' AND is_current LIMIT 1")).scalar() is not None
            status = "failed_using_last_known_good" if has_current else "failed_no_snapshot"
            record_state(db, status, exc.code[:64])
            return {"state": status}
    finally:
        db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK})


def _record_once(db, status: str) -> None:
    recent = db.execute(
        text(
            """
            SELECT 1 FROM observatory_runs
            WHERE source = 'dshield' AND status = :status
              AND started_at > now() - interval '15 minutes' LIMIT 1
            """
        ),
        {"status": status},
    ).scalar()
    if recent is None:
        record_state(db, status)
