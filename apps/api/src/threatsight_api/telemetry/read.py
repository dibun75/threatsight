"""Read persisted Radar snapshots. This module never sees the token."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from threatsight_api.telemetry.contract import LABEL, LIMITATIONS

FRESH = timedelta(minutes=45)


def activity(db: Session) -> dict:
    run = db.execute(
        text(
            """
            SELECT status, error_code, started_at, finished_at
            FROM telemetry_runs
            WHERE source = 'cloudflare_radar'
            ORDER BY started_at DESC
            LIMIT 1
            """
        )
    ).mappings().first()
    success = db.execute(
        text(
            """
            SELECT finished_at FROM telemetry_runs
            WHERE source = 'cloudflare_radar' AND status = 'succeeded'
            ORDER BY finished_at DESC LIMIT 1
            """
        )
    ).mappings().first()
    state = _state(run, success)
    windows = {label: _window(db, label) for label in ("24h", "7d")}
    current = windows["24h"]
    trend = _points(db, "timeseries", "7d")
    mitigation = _points(db, "mitigation", "24h")
    meta = _meta(db, "origin", "24h")
    return {
        "mode": "global_attack_activity",
        "measurement": LABEL,
        "window": "24h",
        "state": state,
        "connected": state in {"current", "stale", "no_data_returned", "failed_using_last_known_good"},
        "last_success_at": _iso(success["finished_at"]) if success else None,
        "last_attempt_at": _iso(run["finished_at"] or run["started_at"]) if run else None,
        "primary": {
            "label": LABEL,
            "state": state,
            "limitations": LIMITATIONS,
            "normalization": meta["normalization"] if meta else None,
            "units": meta["units"] if meta else None,
            "confidence": meta["confidence"] if meta else None,
            "source_updated_at": _iso(meta["source_updated_at"]) if meta else None,
            "comparison": _comparison(db),
        },
        "items": current["items"],
        "targets": current["targets"],
        "paths": current["paths"],
        "windows": windows,
        "trend": trend,
        "mitigation": mitigation,
        "norway": current["norway"],
        "does_not_mean": "This is Cloudflare-observed mitigated traffic. It is not organization exposure and not every attack on the Internet.",
    }


def _state(run, success) -> str:
    if run is None:
        return "disabled"
    status = run["status"]
    if status in {"disabled", "externally_gated", "collecting", "failed_no_snapshot", "failed_using_last_known_good"}:
        return status
    if status != "succeeded" or success is None:
        return "failed_no_snapshot" if success is None else "failed_using_last_known_good"
    finished = success["finished_at"]
    if finished is not None and finished.tzinfo is None:
        finished = finished.replace(tzinfo=UTC)
    if finished is None or datetime.now(UTC) - finished > FRESH:
        return "stale"
    return "current"


def _points(db: Session, dataset: str, window: str) -> list[dict]:
    rows = db.execute(
        text(
            """
            SELECT point.country_code, point.country_name, point.target_country_code, point.target_country_name,
                   point.value, point.rank, point.note, point.observed_at
            FROM telemetry_points AS point
            JOIN telemetry_snapshots AS snapshot ON snapshot.id = point.snapshot_id
            WHERE snapshot.source = 'cloudflare_radar' AND snapshot.dataset = :dataset
              AND snapshot.window_label = :window AND snapshot.is_current
            ORDER BY point.rank NULLS LAST, point.value DESC NULLS LAST, point.country_code
            LIMIT 100
            """
        ),
        {"dataset": dataset, "window": window},
    ).mappings()
    return [
        {
            "country": row["country_code"],
            "name": row["country_name"],
            "target": row["target_country_code"],
            "target_name": row["target_country_name"],
            "value": row["value"],
            "rank": row["rank"],
            "note": row["note"],
            "observed_at": _iso(row["observed_at"]),
        }
        for row in rows
    ]


def _window(db: Session, window: str) -> dict:
    meta = _meta(db, "origin", window)
    return {
        "items": _points(db, "origin", window),
        "targets": _points(db, "target", window),
        "paths": _points(db, "pairs", window),
        "normalization": meta["normalization"] if meta else None,
        "units": meta["units"] if meta else None,
        "confidence": meta["confidence"] if meta else None,
        "source_updated_at": _iso(meta["source_updated_at"]) if meta else None,
        "norway": {
            "origin": _norway(db, "norway_origin", window),
            "target": _norway(db, "norway_target", window),
        },
    }


def _norway(db: Session, dataset: str, window: str) -> dict:
    rows = [row for row in _points(db, dataset, window) if row["country"] == "NO"]
    snapshot = _meta(db, dataset, window)
    if snapshot is None:
        return {"country": "NO", "name": "Norway", "value": None, "state": "no_snapshot", "detail": "No validated snapshot is available."}
    if not rows or rows[0]["value"] is None:
        return {"country": "NO", "name": "Norway", "value": None, "state": "no_data_returned", "detail": "No data returned for Norway in this window."}
    value = rows[0]["value"]
    detail = "Cloudflare returned zero for Norway." if value == 0 else "Norway's share of the stored Cloudflare ranking. This does not mean the organization was targeted."
    return {"country": "NO", "name": "Norway", "value": value, "state": "zero" if value == 0 else "current", "detail": detail}


def _meta(db: Session, dataset: str, window: str):
    return db.execute(
        text(
            """
            SELECT normalization, units, source_updated_at, freshness, confidence
            FROM telemetry_snapshots
            WHERE source = 'cloudflare_radar' AND dataset = :dataset AND window_label = :window AND is_current
            LIMIT 1
            """
        ),
        {"dataset": dataset, "window": window},
    ).mappings().first()


def _comparison(db: Session) -> str:
    rows = db.execute(
        text(
            """
            SELECT retrieved_at FROM telemetry_snapshots
            WHERE source = 'cloudflare_radar' AND dataset = 'timeseries' AND window_label = '24h'
            ORDER BY retrieved_at DESC LIMIT 2
            """
        )
    ).all()
    if len(rows) < 2:
        return "Comparison unavailable."
    return "A previous equivalent snapshot is stored. Compare the stored values; this response does not invent a delta."


def _iso(value) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)
