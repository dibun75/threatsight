"""Publish a complete Radar collection atomically. A failure leaves the current snapshot."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import text

from threatsight_api.telemetry.contract import LIMITATIONS, parse_document

DATASETS = (
    ("timeseries", "timeseries", None),
    ("origin", "origin", None),
    ("target", "target", None),
    ("pairs", "pairs", None),
    ("mitigation", "mitigation", None),
)


def collect_window(window: str, fetch) -> dict[str, dict]:
    collected = {}
    for name, dataset, location in DATASETS:
        _status, payload = fetch(dataset, window, location=location)
        collected[name] = parse_document(payload, kind=dataset)
    collected["norway_origin"] = _country_slice(collected["origin"], "NO")
    collected["norway_target"] = _country_slice(collected["target"], "NO")
    return collected


def _country_slice(document: dict, code: str) -> dict:
    return {"meta": document["meta"], "rows": [row for row in document["rows"] if row.get("country") == code]}


def publish(connection, collected: dict[str, dict], *, window: str) -> None:
    now = datetime.now(UTC)
    run_id = str(uuid.uuid4())
    connection.execute(
        text(
            """
            INSERT INTO telemetry_runs (id, source, status, error_code, window_label, started_at, finished_at)
            VALUES (:id, 'cloudflare_radar', 'succeeded', NULL, :window, :now, :now)
            """
        ),
        {"id": run_id, "window": window, "now": now},
    )
    for name, document in collected.items():
        meta = document["meta"]
        snapshot_id = str(uuid.uuid4())
        body = json.dumps(document, sort_keys=True).encode()
        connection.execute(
            text(
                """
                UPDATE telemetry_snapshots SET is_current = false
                 WHERE source = 'cloudflare_radar' AND dataset = :dataset AND window_label = :window AND is_current
                """
            ),
            {"dataset": name, "window": window},
        )
        connection.execute(
            text(
                """
                INSERT INTO telemetry_snapshots (
                    id, source, dataset, window_start, window_end, window_label, retrieved_at, source_updated_at,
                    units, normalization, freshness, maturity, limitations, confidence, annotations,
                    content_hash, is_current, run_id
                ) VALUES (
                    :id, 'cloudflare_radar', :dataset, :start, :end, :window, :now, :updated,
                    :units, :normalization, 'fresh', 'live_verified', CAST(:limitations AS jsonb),
                    CAST(:confidence AS jsonb), CAST(:annotations AS jsonb), :digest, true, :run_id
                )
                """
            ),
            {
                "id": snapshot_id,
                "dataset": name,
                "start": meta["window_start"],
                "end": meta["window_end"],
                "window": window,
                "now": now,
                "updated": meta["last_updated"],
                "units": meta["units"],
                "normalization": meta["normalization"],
                "limitations": json.dumps(LIMITATIONS),
                "confidence": json.dumps(meta["confidence"]),
                "annotations": json.dumps(meta["annotations"]),
                "digest": hashlib.sha256(body).hexdigest(),
                "run_id": run_id,
            },
        )
        for row in document["rows"]:
            _point(connection, snapshot_id, name, row)


def record_failure(connection, *, window: str, code: str, has_current: bool) -> str:
    status = "failed_using_last_known_good" if has_current else "failed_no_snapshot"
    connection.execute(
        text(
            """
            INSERT INTO telemetry_runs (id, source, status, error_code, window_label, started_at, finished_at)
            VALUES (:id, 'cloudflare_radar', :status, :code, :window, now(), now())
            """
        ),
        {"id": str(uuid.uuid4()), "status": status, "code": code[:64], "window": window},
    )
    return status


def record_state(connection, status: str) -> None:
    connection.execute(
        text(
            """
            INSERT INTO telemetry_runs (id, source, status, error_code, window_label, started_at, finished_at)
            VALUES (:id, 'cloudflare_radar', :status, NULL, NULL, now(), now())
            """
        ),
        {"id": str(uuid.uuid4()), "status": status},
    )


def _point(connection, snapshot_id: str, dataset: str, row: dict) -> None:
    connection.execute(
        text(
            """
            INSERT INTO telemetry_points (
                id, snapshot_id, role, country_code, country_name, target_country_code, target_country_name,
                value, rank, note, observed_at
            ) VALUES (
                :id, :snapshot, :role, :code, :name, :target, :target_name, :value, :rank, :note, :observed
            )
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "snapshot": snapshot_id,
            "role": dataset,
            "code": row.get("country") or row.get("origin"),
            "name": row.get("name") or row.get("origin_name") or row.get("product"),
            "target": row.get("target"),
            "target_name": row.get("target_name"),
            "value": row.get("value"),
            "rank": row.get("rank"),
            "note": row.get("product") or "",
            "observed": row.get("observed_at"),
        },
    )
