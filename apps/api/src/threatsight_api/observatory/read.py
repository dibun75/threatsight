"""Read the current public-observation snapshot without collecting upstream data."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def observations(db: Session, *, limit: int = 100) -> dict:
    run = (
        db.execute(
            text(
                """
            SELECT id, status, error_code, retrieved_at, finished_at, attribution, terms_state, annotations
            FROM observatory_runs WHERE source = 'dshield'
            ORDER BY started_at DESC LIMIT 1
            """
            )
        )
        .mappings()
        .first()
    )
    current = (
        db.execute(
            text(
                """
            SELECT id, retrieved_at, attribution, terms_state, annotations
            FROM observatory_runs WHERE source = 'dshield' AND is_current AND status = 'succeeded'
            LIMIT 1
            """
            )
        )
        .mappings()
        .first()
    )
    if current is None:
        return {
            "source": "dshield",
            "state": run["status"] if run else "disabled",
            "connected": False,
            "retrieved_at": None,
            "attribution": "SANS Internet Storm Center / DShield",
            "terms_state": "attribution_required_no_resale",
            "items": [],
            "categories": [],
            "ports": [],
            "does_not_mean": "No current snapshot. Public observations are not customer traffic or proof of compromise.",
        }
    rows = list(
        db.execute(
            text(
                """
            SELECT kind, indicator_type, indicator, port, service, category, country_code, first_seen, last_seen, detail,
                   count, rank, observed_at, reference_url, confidence
            FROM observatory_observations
            WHERE run_id = :run_id
            ORDER BY CASE WHEN kind = 'reported_infrastructure' THEN 0 WHEN kind = 'scanning_source' THEN 1 ELSE 2 END,
                     rank NULLS LAST, indicator
            LIMIT :limit
            """
            ),
            {"run_id": current["id"], "limit": max(1, min(limit, 250))},
        ).mappings()
    )
    categories = list(
        db.execute(
            text(
                """
            SELECT category, count(*) AS count FROM observatory_observations
            WHERE run_id = :run_id AND indicator_type = 'ipv4'
            GROUP BY category ORDER BY count DESC, category LIMIT 12
            """
            ),
            {"run_id": current["id"]},
        ).mappings()
    )
    ports = list(
        db.execute(
            text(
                """
            SELECT port, service, detail, rank FROM observatory_observations
            WHERE run_id = :run_id AND indicator_type = 'port'
            ORDER BY rank NULLS LAST, port LIMIT 12
            """
            ),
            {"run_id": current["id"]},
        ).mappings()
    )
    return {
        "source": "dshield",
        "state": "current"
        if run and run["status"] == "succeeded"
        else "failed_using_last_known_good",
        "connected": True,
        "retrieved_at": _iso(current["retrieved_at"]),
        "attribution": current["attribution"],
        "terms_state": current["terms_state"],
        "annotations": current["annotations"],
        "items": [
            {**dict(row), "observed_at": _iso(row["observed_at"])}
            for row in rows
            if row["indicator_type"] != "port"
        ],
        "categories": [dict(row) for row in categories],
        "ports": [dict(row) for row in ports],
        "countries": _countries(db, current["id"]),
        "does_not_mean": "These are publicly reported scanning or infrastructure signals. They are not proof that the organization was targeted, reached, or compromised.",
    }


def _iso(value) -> str | None:
    return (
        value.isoformat() if value is not None and hasattr(value, "isoformat") else None
    )


def threatfox_observations(db: Session, *, limit: int = 50) -> dict:
    latest = (
        db.execute(
            text(
                "SELECT status, error_code FROM observatory_runs WHERE source='threatfox' ORDER BY started_at DESC LIMIT 1"
            )
        )
        .mappings()
        .first()
    )
    current = (
        db.execute(
            text(
                "SELECT id, retrieved_at, attribution, terms_state, annotations FROM observatory_runs WHERE source='threatfox' AND is_current AND status='succeeded' LIMIT 1"
            )
        )
        .mappings()
        .first()
    )
    if current is None:
        return {
            "source": "threatfox",
            "state": (latest["error_code"] or latest["status"])
            if latest
            else "disabled",
            "connected": False,
            "retrieved_at": None,
            "attribution": "abuse.ch ThreatFox",
            "terms_state": "usage_authorization_required",
            "items": [],
            "does_not_mean": "No current snapshot. Malware infrastructure reports are not customer traffic or proof of compromise.",
        }
    rows = db.execute(
        text(
            "SELECT indicator_type, indicator, port, category, first_seen, last_seen, detail, rank, reference_url, confidence, metadata_safe FROM observatory_observations WHERE run_id=:run_id ORDER BY last_seen DESC NULLS LAST, rank NULLS LAST, indicator LIMIT :limit"
        ),
        {"run_id": current["id"], "limit": max(1, min(limit, 100))},
    ).mappings()
    return {
        "source": "threatfox",
        "state": "current"
        if latest and latest["status"] == "succeeded"
        else "failed_using_last_known_good",
        "connected": True,
        "retrieved_at": _iso(current["retrieved_at"]),
        "attribution": current["attribution"],
        "terms_state": current["terms_state"],
        "annotations": current["annotations"],
        "items": [
            {
                **{
                    key: value
                    for key, value in dict(row).items()
                    if key != "metadata_safe"
                },
                **(row["metadata_safe"] or {}),
                "first_seen": _iso(row["first_seen"]),
                "last_seen": _iso(row["last_seen"]),
            }
            for row in rows
        ],
        "does_not_mean": "Source-reported malware infrastructure is not attacker attribution or proof that this organization was targeted, reached, or compromised.",
    }


def _countries(db: Session, run_id) -> list[dict]:
    rows = db.execute(
        text(
            """
            SELECT country_code AS country, count(*) AS count
            FROM observatory_observations
            WHERE run_id = :run_id AND country_code IS NOT NULL
            GROUP BY country_code ORDER BY count DESC, country_code LIMIT 100
            """
        ),
        {"run_id": run_id},
    ).mappings()
    return [dict(row) for row in rows]


_ABUSECH = {"feodo": "abuse.ch Feodo Tracker", "urlhaus": "abuse.ch URLhaus"}


def abusech_observations(db: Session, feed: str, *, limit: int = 100) -> dict:
    """Current abuse.ch snapshot. Feodo rows carry the source-supplied hosting country; URLhaus rows never do."""
    latest = db.execute(text("SELECT status, error_code FROM observatory_runs WHERE source=:s ORDER BY started_at DESC LIMIT 1"), {"s": feed}).mappings().first()
    current = db.execute(text("SELECT id, retrieved_at, attribution, terms_state, annotations FROM observatory_runs WHERE source=:s AND is_current AND status='succeeded' LIMIT 1"), {"s": feed}).mappings().first()
    meaning = "Source-reported malware infrastructure is not attacker attribution or proof that this organization was targeted, reached, or compromised."
    if current is None:
        return {"source": feed, "state": (latest["error_code"] or latest["status"]) if latest else "disabled", "connected": False, "retrieved_at": None, "attribution": _ABUSECH[feed], "items": [], "countries": [], "does_not_mean": meaning}
    rows = db.execute(
        text("SELECT indicator_type, indicator, port, category, country_code, first_seen, last_seen, detail, rank, reference_url, metadata_safe FROM observatory_observations WHERE run_id=:r ORDER BY last_seen DESC NULLS LAST, rank NULLS LAST, indicator LIMIT :limit"),
        {"r": current["id"], "limit": max(1, min(limit, 250))},
    ).mappings()
    return {
        "source": feed,
        "state": "current" if latest and latest["status"] == "succeeded" else "failed_using_last_known_good",
        "connected": True,
        "retrieved_at": _iso(current["retrieved_at"]),
        "attribution": current["attribution"],
        "terms_state": current["terms_state"],
        "annotations": current["annotations"],
        "items": [
            {**{k: v for k, v in dict(row).items() if k != "metadata_safe"}, **(row["metadata_safe"] or {}), "first_seen": _iso(row["first_seen"]), "last_seen": _iso(row["last_seen"])}
            for row in rows
        ],
        "countries": _countries(db, current["id"]),
        "does_not_mean": meaning,
    }
