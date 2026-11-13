from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import (
    OrganizationProfile,
    ThreatEvent,
    ThreatRelevance,
    ThreatSource,
    VulnerabilitySignal,
)
from threatsight_api.radar.contracts import ManualThreatEventIn, NormalizedThreatEvent
from threatsight_api.radar.clustering import recompute_clusters
from threatsight_api.radar.fetch import fetch_source
from threatsight_api.radar.parsers import (
    parse_authority_rss,
    parse_cert_se_atom,
    parse_cisa_kev,
    parse_enisa_euvd,
    parse_first_epss,
    parse_nsm_rss,
)
from threatsight_api.radar.relevance import score_relevance


def _content_hash(event: NormalizedThreatEvent) -> str:
    payload = event.model_dump(mode="json")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _upsert_event(
    session: Session, source: ThreatSource, event: NormalizedThreatEvent
) -> tuple[ThreatEvent, str]:
    record = session.scalar(
        select(ThreatEvent).where(
            ThreatEvent.source_id == source.id,
            ThreatEvent.external_id == event.external_id,
        )
    )
    created = record is None
    content_hash = _content_hash(event)
    unchanged = record is not None and record.content_hash == content_hash
    if record is None:
        record = ThreatEvent(source_id=source.id, external_id=event.external_id)
        session.add(record)
    record.event_type = event.event_type
    record.title = event.title
    record.summary = event.summary
    record.canonical_url = str(event.canonical_url)
    record.published_at = event.published_at
    record.source_updated_at = event.source_updated_at
    record.ingested_at = datetime.now(UTC)
    record.content_hash = content_hash
    record.confidence = event.confidence
    record.countries = event.countries
    record.authority_jurisdictions = event.authority_jurisdictions
    record.target_countries = event.target_countries
    record.victim_countries = event.victim_countries
    record.infrastructure_countries = event.infrastructure_countries
    record.prevalence_countries = event.prevalence_countries
    record.sectors = event.sectors
    record.vendors = event.vendors
    record.products = event.products
    record.technologies = event.technologies
    record.cves = event.cves
    record.exploitation_status = event.exploitation_status
    record.source_payload_hash = event.source_payload_hash
    record.parser_version = event.parser_version
    record.provenance = event.provenance
    record.limitations = event.limitations
    record.attributes = event.attributes
    session.flush()
    return record, "created" if created else ("unchanged" if unchanged else "updated")


def _upsert_epss(
    session: Session,
    values: dict[str, tuple[float, float, datetime | None]],
) -> int:
    changed = 0
    for cve, (score, percentile, score_date) in values.items():
        record = session.scalar(select(VulnerabilitySignal).where(VulnerabilitySignal.cve == cve))
        if record is None:
            record = VulnerabilitySignal(cve=cve, epss_score=score, percentile=percentile)
            session.add(record)
            changed += 1
        elif (
            record.epss_score != score
            or record.percentile != percentile
            or record.score_date != score_date
        ):
            changed += 1
        record.epss_score = score
        record.percentile = percentile
        record.score_date = score_date
        record.source = "first-epss"
    session.flush()
    return changed


def recompute_relevance(session: Session) -> int:
    profiles = list(session.scalars(select(OrganizationProfile)))
    events = list(session.scalars(select(ThreatEvent)))
    signals = {item.cve: item.epss_score for item in session.scalars(select(VulnerabilitySignal))}
    changed = 0
    for profile in profiles:
        for event in events:
            result = score_relevance(profile, event, [signals[cve] for cve in event.cves if cve in signals])
            record = session.scalar(
                select(ThreatRelevance).where(
                    ThreatRelevance.workspace_id == profile.workspace_id,
                    ThreatRelevance.event_id == event.id,
                )
            )
            if record is None:
                record = ThreatRelevance(workspace_id=profile.workspace_id, event_id=event.id)
                session.add(record)
            record.score = result.score
            record.level = result.level
            record.reasons = result.reasons
            record.matches = result.matches
            record.assessed_at = datetime.now(UTC)
            changed += 1
    session.flush()
    return changed


def import_manual_event(
    session: Session,
    source_key: str,
    body: ManualThreatEventIn,
    actor: str,
) -> dict:
    source = session.scalar(select(ThreatSource).where(ThreatSource.key == source_key))
    if source is None or source.sync_mode != "manual" or not source.enabled:
        raise ValueError("Manual source is unavailable")
    canonical = urlparse(str(body.canonical_url))
    allowed = urlparse(source.locator)
    if (
        canonical.scheme != "https"
        or not canonical.hostname
        or not allowed.hostname
        or (
            canonical.hostname != allowed.hostname
            and not canonical.hostname.endswith(f".{allowed.hostname}")
        )
    ):
        raise ValueError("Canonical URL is outside the manual source authority")
    jurisdiction = [source.jurisdiction] if source.jurisdiction else []
    payload = body.model_dump(mode="json")
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    normalized = body.model_dump(exclude={"limitations"})
    event = NormalizedThreatEvent(
        **normalized,
        countries=sorted(set(jurisdiction + body.target_countries + body.victim_countries)),
        authority_jurisdictions=jurisdiction,
        source_payload_hash=digest,
        parser_version=source.parser_version,
        provenance={
            "authority": source.authority,
            "import_mode": "manual_metadata",
            "imported_by": actor,
        },
        limitations=sorted(
            set(
                body.limitations
                + [
                    "Manually imported metadata was not independently verified by ThreatSight.",
                    "Authority jurisdiction does not identify attacker origin.",
                ]
            )
        ),
    )
    record, outcome = _upsert_event(session, source, event)
    recompute_clusters(session)
    recompute_relevance(session)
    return {"id": str(record.id), "source": source_key, "outcome": outcome}


def sync_source(session: Session, source_key: str) -> dict:
    source = session.scalar(select(ThreatSource).where(ThreatSource.key == source_key))
    if source is None or not source.enabled:
        return {"status": "failed", "error": "Source is unavailable", "source": source_key}
    try:
        created = 0
        updated = 0
        unchanged = 0
        enriched = 0
        if source_key == "cisa-kev":
            events = parse_cisa_kev(fetch_source(source_key))
        elif source_key == "nsm-rss":
            events = parse_nsm_rss(fetch_source(source_key))
        elif source_key == "cert-se-atom":
            events = parse_cert_se_atom(fetch_source(source_key))
        elif source_key == "ncsc-fi-rss":
            events = parse_authority_rss(
                fetch_source(source_key),
                authority="NCSC-FI",
                jurisdiction="FI",
                language="fi",
            )
        elif source_key == "cert-eu-rss":
            events = parse_authority_rss(
                fetch_source(source_key),
                authority="CERT-EU",
                jurisdiction="EU",
                language="en",
            )
        elif source_key == "enisa-euvd":
            events = parse_enisa_euvd(fetch_source(source_key, query={"page": 0, "size": 100}))
        elif source_key == "first-epss":
            cves = sorted({cve for event in session.scalars(select(ThreatEvent)) for cve in event.cves})
            for start in range(0, len(cves), 100):
                enriched += _upsert_epss(
                    session,
                    parse_first_epss(fetch_source(source_key, cves[start : start + 100])),
                )
            events = []
        else:
            return {"status": "failed", "error": "Unknown source", "source": source_key}

        for event in events:
            _, outcome = _upsert_event(session, source, event)
            created += int(outcome == "created")
            updated += int(outcome == "updated")
            unchanged += int(outcome == "unchanged")
        clustering = recompute_clusters(session)
        relevance = recompute_relevance(session)
        source.last_synced_at = datetime.now(UTC)
        source.last_status = "ok"
        source.last_error = None
        source.last_success_at = source.last_synced_at
        source.consecutive_failures = 0
        return {
            "status": "ok",
            "source": source_key,
            "created": created,
            "updated": updated,
            "unchanged": unchanged,
            "enriched": enriched,
            "relevance_assessments": relevance,
            **clustering,
        }
    except Exception as exc:
        source.last_synced_at = datetime.now(UTC)
        source.last_status = "failed"
        source.last_error = str(exc)[:500]
        source.consecutive_failures = (source.consecutive_failures or 0) + 1
        return {
            "status": "failed",
            "source": source_key,
            "error": str(exc)[:500],
        }
