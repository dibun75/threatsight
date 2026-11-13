"""Atomic publication of bounded public observations."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import text

ATTRIBUTION = "SANS Internet Storm Center / DShield"
TERMS_STATE = "attribution_required_no_resale"


def publish(connection, rows: list[dict]) -> str:
    now = datetime.now(UTC)
    run_id = str(uuid.uuid4())
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    connection.execute(text("UPDATE observatory_runs SET is_current = false WHERE source = 'dshield' AND is_current"))
    connection.execute(
        text(
            """
            INSERT INTO observatory_runs (
                id, source, status, started_at, finished_at, retrieved_at, attribution,
                terms_state, content_hash, is_current, annotations
            ) VALUES (
                :id, 'dshield', 'succeeded', :now, :now, :now, :attribution,
                :terms, :digest, true, CAST(:annotations AS jsonb)
            )
            """
        ),
        {
            "id": run_id,
            "now": now,
            "attribution": ATTRIBUTION,
            "terms": TERMS_STATE,
            "digest": hashlib.sha256(canonical).hexdigest(),
            "annotations": json.dumps([
                "Publicly reported global observations, not customer traffic.",
                "An IP observation is not attacker attribution or proof of compromise.",
                "Attribution is required and source data must not be resold.",
            ]),
        },
    )
    for row in rows:
        connection.execute(
            text(
                """
                INSERT INTO observatory_observations (
                    id, run_id, source, kind, indicator_type, indicator, port, service,
                    category, country_code, first_seen, last_seen, detail, count, rank, observed_at, reference_url, confidence, metadata_safe
                ) VALUES (
                    :id, :run_id, 'dshield', :kind, :indicator_type, :indicator, :port, :service,
                    :category, :country_code, :first_seen, :last_seen, :detail, :count, :rank, :observed_at, :reference_url,
                    'source_reported', CAST(:metadata_safe AS jsonb)
                )
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "run_id": run_id,
                "kind": row["kind"],
                "indicator_type": row["indicator_type"],
                "indicator": row["indicator"],
                "port": row.get("port"),
                "service": row.get("service"),
                "category": row["category"],
                "country_code": row.get("country_code"),
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
                "detail": row.get("detail", ""),
                "count": row.get("count"),
                "rank": row.get("rank"),
                "observed_at": row.get("observed_at"),
                "reference_url": row["reference_url"],
                "metadata_safe": json.dumps({}),
            },
        )
    return run_id


def record_state(connection, status: str, code: str | None = None) -> None:
    connection.execute(
        text(
            """
            INSERT INTO observatory_runs (
                id, source, status, error_code, started_at, finished_at, attribution, terms_state, is_current
            ) VALUES (:id, 'dshield', :status, :code, now(), now(), :attribution, :terms, false)
            """
        ),
        {"id": str(uuid.uuid4()), "status": status, "code": code, "attribution": ATTRIBUTION, "terms": TERMS_STATE},
    )
