"""Usage-gated ThreatFox collection in the outbound intelligence worker."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
import uuid

from sqlalchemy import text

from threatsight_api.observatory.contract import ObservatoryError
from threatsight_api.observatory.threatfox import fetch_recent, parse_recent

SOURCE = "threatfox"
ATTRIBUTION = "abuse.ch ThreatFox"
TERMS_STATE = "usage_authorization_required"
ALLOWED_USAGE_MODES = {"personal_evaluation", "commercial_entitled"}
LOCK = 213013
INTERVAL_MINUTES = 60


def maybe_collect(
    db,
    *,
    enabled: bool | None = None,
    usage_mode: str | None = None,
    fetch=fetch_recent,
) -> dict:
    enabled = _flag("THREATSIGHT_THREATFOX_ENABLED") if enabled is None else enabled
    usage_mode = (
        (
            os.environ.get("THREATSIGHT_THREATFOX_USAGE_MODE", "")
            if usage_mode is None
            else usage_mode
        )
        .strip()
        .lower()
    )
    if not enabled:
        _record_once(db, "disabled")
        return {"state": "disabled"}
    if usage_mode not in ALLOWED_USAGE_MODES:
        _record_once(db, "disabled", TERMS_STATE)
        return {"state": TERMS_STATE}
    if _flag("THREATSIGHT_INTEL_KILL_SWITCH"):
        _record_once(db, "disabled", "kill_switch")
        return {"state": "disabled"}
    token_file = os.environ.get("THREATSIGHT_THREATFOX_AUTH_KEY_FILE", "")
    if not token_file:
        _record_once(db, "failed_no_snapshot", "credential_unavailable")
        return {"state": "failed_no_snapshot"}
    if not db.execute(
        text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK}
    ).scalar():
        return {"state": "collecting"}
    try:
        recent = db.execute(
            text(
                "SELECT 1 FROM observatory_runs WHERE source=:source AND status='succeeded' AND started_at > now() - make_interval(mins => :minutes) LIMIT 1"
            ),
            {"source": SOURCE, "minutes": INTERVAL_MINUTES},
        ).scalar()
        if recent:
            return {"state": "current"}
        try:
            rows = parse_recent(fetch(token_file, days=1))
            if not rows:
                raise ObservatoryError("empty_result")
            _publish(db, rows, usage_mode=usage_mode)
            return {"state": "current", "count": len(rows)}
        except ObservatoryError as exc:
            current = db.execute(
                text(
                    "SELECT 1 FROM observatory_runs WHERE source=:source AND is_current LIMIT 1"
                ),
                {"source": SOURCE},
            ).scalar()
            status = "failed_using_last_known_good" if current else "failed_no_snapshot"
            _record(db, status, exc.code[:64])
            return {"state": status}
    finally:
        db.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK})


def _publish(db, rows: list[dict], *, usage_mode: str) -> None:
    now, run_id = datetime.now(UTC), str(uuid.uuid4())
    digest = hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    db.execute(
        text(
            "UPDATE observatory_runs SET is_current=false WHERE source=:source AND is_current"
        ),
        {"source": SOURCE},
    )
    db.execute(
        text(
            "INSERT INTO observatory_runs (id,source,status,started_at,finished_at,retrieved_at,attribution,terms_state,content_hash,is_current,annotations) VALUES (:id,:source,'succeeded',:now,:now,:now,:attribution,:terms,:digest,true,CAST(:annotations AS jsonb))"
        ),
        {
            "id": run_id,
            "source": SOURCE,
            "now": now,
            "attribution": ATTRIBUTION,
            "terms": usage_mode,
            "digest": digest,
            "annotations": json.dumps(
                [
                    "Recent source-reported malware infrastructure, not customer traffic.",
                    "An IOC is not attacker attribution or proof of customer impact.",
                    "Personal-evaluation data must not be resold or used in a commercial service without the required entitlement.",
                ]
            ),
        },
    )
    statement = text(
        "INSERT INTO observatory_observations (id,run_id,source,kind,indicator_type,indicator,port,category,first_seen,last_seen,detail,rank,reference_url,confidence,metadata_safe) VALUES (:id,:run_id,:source,:kind,:indicator_type,:indicator,:port,:category,:first_seen,:last_seen,:detail,:rank,:reference_url,'source_reported',CAST(:metadata_safe AS jsonb))"
    )
    for row in rows:
        db.execute(
            statement,
            {
                "id": str(uuid.uuid4()),
                "run_id": run_id,
                "source": SOURCE,
                "kind": row["kind"],
                "indicator_type": row["indicator_type"],
                "indicator": row["indicator"],
                "port": row.get("port"),
                "category": row["category"],
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
                "detail": row["detail"],
                "rank": row["rank"],
                "reference_url": row["reference_url"],
                "metadata_safe": json.dumps(row["metadata_safe"]),
            },
        )


def _record(db, status: str, code: str | None = None) -> None:
    db.execute(
        text(
            "INSERT INTO observatory_runs (id,source,status,error_code,started_at,finished_at,attribution,terms_state,is_current) VALUES (:id,:source,:status,:code,now(),now(),:attribution,:terms,false)"
        ),
        {
            "id": str(uuid.uuid4()),
            "source": SOURCE,
            "status": status,
            "code": code,
            "attribution": ATTRIBUTION,
            "terms": TERMS_STATE,
        },
    )


def _record_once(db, status: str, code: str | None = None) -> None:
    exists = db.execute(
        text(
            "SELECT 1 FROM observatory_runs WHERE source=:source AND status=:status AND error_code IS NOT DISTINCT FROM :code AND started_at > now() - interval '15 minutes' LIMIT 1"
        ),
        {"source": SOURCE, "status": status, "code": code},
    ).scalar()
    if exists is None:
        _record(db, status, code)


def _flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes"}
