"""Collection of the abuse.ch Feodo Tracker and URLhaus recent feeds in the outbound intelligence worker."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
import uuid

from sqlalchemy import text

from threatsight_api.observatory.abusech import PARSERS, fetch_feed
from threatsight_api.observatory.contract import ObservatoryError

ATTRIBUTION = {"feodo": "abuse.ch Feodo Tracker", "urlhaus": "abuse.ch URLhaus"}
ENV_FLAG = {"feodo": "THREATSIGHT_FEODO_ENABLED", "urlhaus": "THREATSIGHT_URLHAUS_ENABLED"}
LOCK = {"feodo": 213014, "urlhaus": 213015}
TERMS_STATE = "cc0_attribution_requested"
INTERVAL_MINUTES = 30
KEY_FILE_ENV = "THREATSIGHT_ABUSECH_AUTH_KEY_FILE"


def maybe_collect(db, feed: str, *, enabled: bool | None = None, fetch=fetch_feed) -> dict:
    enabled = _flag(ENV_FLAG[feed]) if enabled is None else enabled
    if not enabled:
        _record_once(db, feed, "disabled")
        return {"state": "disabled"}
    if _flag("THREATSIGHT_INTEL_KILL_SWITCH"):
        _record_once(db, feed, "disabled", "kill_switch")
        return {"state": "disabled"}
    if not db.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK[feed]}).scalar():
        return {"state": "collecting"}
    try:
        recent = db.execute(
            text("SELECT 1 FROM observatory_runs WHERE source=:source AND status='succeeded' AND started_at > now() - make_interval(mins => :minutes) LIMIT 1"),
            {"source": feed, "minutes": INTERVAL_MINUTES},
        ).scalar()
        if recent:
            return {"state": "current"}
        try:
            rows = PARSERS[feed](fetch(feed, os.environ.get(KEY_FILE_ENV, "")))
            if not rows:
                raise ObservatoryError("empty_result")
            _publish(db, feed, rows)
            return {"state": "current", "count": len(rows)}
        except ObservatoryError as exc:
            current = db.execute(text("SELECT 1 FROM observatory_runs WHERE source=:source AND is_current LIMIT 1"), {"source": feed}).scalar()
            status = "failed_using_last_known_good" if current else "failed_no_snapshot"
            _record(db, feed, status, exc.code[:64])
            return {"state": status}
    finally:
        db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK[feed]})


def _publish(db, feed: str, rows: list[dict]) -> None:
    now, run_id = datetime.now(UTC), str(uuid.uuid4())
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    db.execute(text("UPDATE observatory_runs SET is_current=false WHERE source=:source AND is_current"), {"source": feed})
    db.execute(
        text("INSERT INTO observatory_runs (id,source,status,started_at,finished_at,retrieved_at,attribution,terms_state,content_hash,is_current,annotations) VALUES (:id,:source,'succeeded',:now,:now,:now,:attribution,:terms,:digest,true,CAST(:annotations AS jsonb))"),
        {
            "id": run_id, "source": feed, "now": now, "attribution": ATTRIBUTION[feed], "terms": TERMS_STATE, "digest": digest,
            "annotations": json.dumps([
                "Recent source-reported malware infrastructure, not customer traffic.",
                "An indicator is not attacker attribution or proof of customer impact.",
            ]),
        },
    )
    statement = text(
        "INSERT INTO observatory_observations (id,run_id,source,kind,indicator_type,indicator,port,category,country_code,first_seen,last_seen,detail,rank,reference_url,confidence,metadata_safe) VALUES (:id,:run_id,:source,:kind,:indicator_type,:indicator,:port,:category,:country_code,:first_seen,:last_seen,:detail,:rank,:reference_url,'source_reported',CAST(:metadata_safe AS jsonb))"
    )
    for row in rows:
        db.execute(statement, {
            "id": str(uuid.uuid4()), "run_id": run_id, "source": feed, "kind": row["kind"],
            "indicator_type": row["indicator_type"], "indicator": row["indicator"], "port": row.get("port"),
            "category": row["category"], "country_code": row.get("country_code"),
            "first_seen": row.get("first_seen"), "last_seen": row.get("last_seen"),
            "detail": row["detail"], "rank": row["rank"], "reference_url": row["reference_url"],
            "metadata_safe": json.dumps(row["metadata_safe"]),
        })


def _record(db, feed: str, status: str, code: str | None = None) -> None:
    db.execute(
        text("INSERT INTO observatory_runs (id,source,status,error_code,started_at,finished_at,attribution,terms_state,is_current) VALUES (:id,:source,:status,:code,now(),now(),:attribution,:terms,false)"),
        {"id": str(uuid.uuid4()), "source": feed, "status": status, "code": code, "attribution": ATTRIBUTION[feed], "terms": TERMS_STATE},
    )


def _record_once(db, feed: str, status: str, code: str | None = None) -> None:
    exists = db.execute(
        text("SELECT 1 FROM observatory_runs WHERE source=:source AND status=:status AND error_code IS NOT DISTINCT FROM :code AND started_at > now() - interval '15 minutes' LIMIT 1"),
        {"source": feed, "status": status, "code": code},
    ).scalar()
    if exists is None:
        _record(db, feed, status, code)


def _flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes"}
