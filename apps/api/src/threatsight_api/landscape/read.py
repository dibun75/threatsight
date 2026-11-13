from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.landscape.priority import priority_reason
from threatsight_api.landscape.sanitize import plain
from threatsight_api.landscape.versioning import compare_version
from threatsight_api.persistence.correlation_models import CorrelationMatch, CorrelationRun
from threatsight_api.persistence.landscape_models import LandscapeAdvisory, LandscapeCatalog
from threatsight_api.persistence.models import ThreatSource

DOES_NOT_MEAN = (
    "Counts are advisory or warning records in the selected role. "
    "They are not attacks, not attacker origin, and not a national risk score."
)
ROLES = {
    "authority_jurisdiction",
    "advisory_jurisdiction",
    "affected_jurisdiction",
    "national_alert",
    "asset_location",
}


def _matches(db: Session, workspace_id: uuid.UUID) -> list[CorrelationMatch]:
    run_id = db.scalar(
        select(CorrelationRun.id).where(
            CorrelationRun.workspace_id == workspace_id,
            CorrelationRun.is_current.is_(True),
        )
    )
    if run_id is None:
        return []
    return list(
        db.scalars(
            select(CorrelationMatch)
            .where(CorrelationMatch.workspace_id == workspace_id, CorrelationMatch.run_id == run_id)
            .order_by(CorrelationMatch.cve, CorrelationMatch.asset_key)
            .limit(200)
        )
    )


def _advisory_out(row: LandscapeAdvisory, matches: list[CorrelationMatch]) -> dict:
    cves = set(row.cves or [])
    related = [item for item in matches if item.cve in cves][:8]
    products = []
    for product in (row.products or [])[:8]:
        result = compare_version(product.get("scheme", ""), product.get("observed"), product.get("constraint"))
        products.append({**product, "comparison": result})
    version_result = products[0]["comparison"] if products else "missing"
    rank, reason = priority_reason(
        version_result=version_result,
        kev=row.kev_listed,
        epss=row.epss_score,
        vendor_severity=row.vendor_severity,
        cvss=row.cvss_score,
        conflict=row.conflict,
    )
    return {
        "id": str(row.id),
        "source_key": row.source_key,
        "external_id": row.external_id,
        "title": plain(row.title, 500),
        "summary": plain(row.summary, 2000),
        "canonical_url": row.canonical_url if str(row.canonical_url).startswith("https://") else None,
        "vendor": plain(row.vendor, 80),
        "vendor_advisory_id": plain(row.vendor_advisory_id, 80),
        "cves": list(row.cves or [])[:20],
        "vendor_severity": row.vendor_severity,
        "cvss_score": row.cvss_score,
        "cvss_vector": row.cvss_vector,
        "cvss_version": row.cvss_version,
        "vex_status": row.vex_status,
        "kev_listed": row.kev_listed,
        "epss_score": row.epss_score,
        "epss_percentile": row.epss_percentile,
        "exploitation_claim": row.exploitation_claim,
        "withdrawn": row.withdrawn,
        "freshness": row.freshness,
        "conflict": row.conflict,
        "maturity": row.maturity,
        "evidence_hash": row.evidence_hash,
        "products": products,
        "geography": list(row.geography or [])[:8],
        "limitations": list(row.limitations or [])[:12],
        "priority_rank": rank,
        "priority_reason": reason,
        "enterprise_context": "synthetic",
        "synthetic_matches": [
            {
                "state": item.state,
                "asset_key": item.asset_key,
                "services": list(item.services or [])[:6],
                "version_evidence": item.version_evidence,
                "explanation": plain(item.explanation, 400),
                "missing_facts": list(item.missing_facts or [])[:8],
            }
            for item in related
        ],
    }


def sources(db: Session) -> dict:
    from sqlalchemy import text

    from threatsight_api.intel.collect import health_for

    rows = list(db.scalars(select(ThreatSource).order_by(ThreatSource.key)))
    schedules = {
        row.source_key: row
        for row in db.execute(text("SELECT * FROM landscape_schedules")).mappings()
    }
    items = []
    for row in rows:
        schedule = schedules.get(row.key)
        health = health_for(
            {
                "source_key": row.key,
                "enabled": bool(schedule["enabled"]) if schedule else False,
                "kill_switch": bool(schedule["kill_switch"]) if schedule else False,
                "maturity": row.maturity,
                "lease_expires_at": schedule["lease_expires_at"] if schedule else None,
                "last_error_code": schedule["last_error_code"] if schedule else None,
                "consecutive_failures": schedule["consecutive_failures"] if schedule else 0,
                "last_success_at": schedule["last_success_at"] if schedule else row.last_success_at,
                "freshness_hours": schedule["freshness_hours"] if schedule else 48,
            }
        )
        items.append(
            {
                "key": row.key,
                "authority": row.authority,
                "locator": row.locator,
                "format": row.source_format,
                "auth_requirement": row.auth_requirement,
                "maturity": row.maturity,
                "health": health,
                "last_status": row.last_status,
                "last_success_at": None if schedule is None else schedule["last_success_at"],
                "next_attempt_at": None if schedule is None else schedule["next_attempt_at"],
                "terms_note": plain(row.terms_note, 500),
                "enabled": row.enabled,
            }
        )
    return {"items": items, "failures_hidden": False}


_MATURITIES = ("live_verified", "fixture_tested", "credential_required", "unsupported")


def summary(db: Session) -> dict:
    rows = list(db.scalars(select(LandscapeAdvisory)))
    buckets = {name: 0 for name in (*_MATURITIES, "unknown")}
    withdrawn = 0
    stale = 0
    for row in rows:
        if row.withdrawn:
            withdrawn += 1
            continue
        if row.freshness == "stale":
            stale += 1
        buckets[row.maturity if row.maturity in _MATURITIES else "unknown"] += 1
    stored = len(rows)
    return {
        "statement": "Authoritative or fixture-tested public intelligence correlated to a synthetic enterprise.",
        "stored_total": stored,
        "included": stored - withdrawn,
        "excluded_withdrawn": withdrawn,
        "stale_included": stale,
        "fixture_tested": buckets["fixture_tested"],
        "live_verified_advisories": buckets["live_verified"],
        "credential_required": buckets["credential_required"],
        "unsupported": buckets["unsupported"],
        "unknown": buckets["unknown"],
        "denominator": (
            "stored_total counts every advisory once. "
            "Withdrawn advisories are excluded from the maturity buckets and counted separately. "
            "Stale advisories remain in their maturity bucket. "
            "Geography exclusions do not change this total."
        ),
        "enterprise_context": "synthetic",
        "time_window": "fixture seed plus collected public advisories",
        "does_not_mean": DOES_NOT_MEAN,
    }


def advisories(db: Session, workspace_id: uuid.UUID, limit: int) -> dict:
    rows = list(
        db.scalars(
            select(LandscapeAdvisory)
            .where(LandscapeAdvisory.withdrawn.is_(False))
            .order_by(LandscapeAdvisory.vendor, LandscapeAdvisory.external_id)
            .limit(min(limit, 50))
        )
    )
    matches = _matches(db, workspace_id)
    items = [_advisory_out(row, matches) for row in rows]
    items.sort(key=lambda item: (item["priority_rank"], item["vendor"], item["external_id"]))
    return {"items": items, "limit": min(limit, 50), "enterprise_context": "synthetic"}


def advisory(db: Session, workspace_id: uuid.UUID, advisory_id: uuid.UUID) -> dict | None:
    row = db.get(LandscapeAdvisory, advisory_id)
    if row is None:
        return None
    return _advisory_out(row, _matches(db, workspace_id))


def geography(db: Session, metric: str) -> dict:
    from threatsight_api.landscape.countries import country_name

    role = metric if metric in ROLES else "authority_jurisdiction"
    counts: dict[str, int] = {}
    maturities: dict[str, dict[str, int]] = {}
    included = 0
    excluded = 0
    unknown = 0
    for row in db.scalars(select(LandscapeAdvisory)):
        if row.withdrawn or row.freshness == "stale":
            excluded += 1
            continue
        included += 1
        matched = False
        for item in row.geography or []:
            code = item.get("country")
            if item.get("role") != role or not isinstance(code, str):
                continue
            name = country_name(code)
            if name is None:
                continue
            matched = True
            counts[code] = counts.get(code, 0) + 1
            band = maturities.setdefault(code, {})
            key = row.maturity if row.maturity in _MATURITIES else "unknown"
            band[key] = band.get(key, 0) + 1
        if not matched:
            unknown += 1
    return {
        "metric": role,
        "meaning": "Authority jurisdiction of the publishing source. This is not a target, victim, infrastructure, or attacker country.",
        "time_window": "Current advisory records. Withdrawn and stale records are excluded.",
        "source_set": "landscape_advisories",
        "included": included,
        "excluded": excluded,
        "unknown_geography": unknown,
        "items": [
            {
                "country": key,
                "name": country_name(key),
                "count": counts[key],
                "state": "recorded",
                "maturities": maturities.get(key, {}),
            }
            for key in sorted(counts)
        ],
        "does_not_mean": DOES_NOT_MEAN,
        "enterprise_context": "synthetic",
    }


def matrix(db: Session) -> dict:
    counts: dict[tuple[str, str], int] = {}
    for row in db.scalars(select(LandscapeAdvisory).where(LandscapeAdvisory.withdrawn.is_(False))):
        for product in row.products or []:
            key = (plain(product.get("vendor"), 80), plain(product.get("family"), 80))
            counts[key] = counts.get(key, 0) + 1
    return {
        "items": [
            {"vendor": vendor, "family": family, "advisories": count}
            for (vendor, family), count in sorted(counts.items())
        ],
        "enterprise_context": "synthetic",
    }


def catalog(db: Session) -> dict:
    rows = list(db.scalars(select(LandscapeCatalog).order_by(LandscapeCatalog.vendor, LandscapeCatalog.product).limit(50)))
    return {
        "items": [
            {
                "vendor": row.vendor,
                "family": row.family,
                "product": row.product,
                "version_scheme": row.version_scheme,
                "aliases": list(row.aliases or []),
            }
            for row in rows
        ],
        "alias_policy": "Catalogue aliases are seeded and scoped. Connector data cannot create them.",
    }
