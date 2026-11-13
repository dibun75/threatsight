from __future__ import annotations

from collections import defaultdict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import (
    RadarReadinessLink,
    RadarTriage,
    ThreatCluster,
    ThreatClusterMembership,
    ThreatEvent,
    ThreatRelevance,
    ThreatSource,
    VulnerabilitySignal,
)
from threatsight_api.radar.contracts import RadarFilterSchema

GEOGRAPHY_FIELDS = {
    "authority": ThreatEvent.authority_jurisdictions,
    "target": ThreatEvent.target_countries,
    "victim": ThreatEvent.victim_countries,
    "infrastructure": ThreatEvent.infrastructure_countries,
    "prevalence": ThreatEvent.prevalence_countries,
}


def query_events(
    session: Session,
    workspace_id,
    filters: RadarFilterSchema,
    profile_minimum: int = 0,
) -> dict:
    threshold = (
        filters.minimum_relevance
        if filters.minimum_relevance is not None
        else profile_minimum
    )
    statement = (
        select(ThreatEvent, ThreatSource, ThreatRelevance)
        .join(ThreatSource, ThreatSource.id == ThreatEvent.source_id)
        .join(ThreatRelevance, ThreatRelevance.event_id == ThreatEvent.id)
        .where(
            ThreatRelevance.workspace_id == workspace_id,
            ThreatRelevance.score >= threshold,
        )
    )
    if filters.source:
        statement = statement.where(ThreatSource.key == filters.source)
    if filters.country:
        country = filters.country.upper()
        if filters.geography == "any":
            statement = statement.where(
                ThreatEvent.authority_jurisdictions.contains([country])
                | ThreatEvent.target_countries.contains([country])
                | ThreatEvent.victim_countries.contains([country])
                | ThreatEvent.infrastructure_countries.contains([country])
                | ThreatEvent.prevalence_countries.contains([country])
            )
        else:
            statement = statement.where(GEOGRAPHY_FIELDS[filters.geography].contains([country]))
    for field in ("sector", "vendor", "product", "technology"):
        value = getattr(filters, field)
        if value:
            column = getattr(ThreatEvent, f"{field}s")
            statement = statement.where(column.contains([value]))
    if filters.event_type:
        statement = statement.where(ThreatEvent.event_type == filters.event_type)
    if filters.exploitation_status:
        statement = statement.where(
            ThreatEvent.exploitation_status == filters.exploitation_status
        )
    if filters.relevance:
        statement = statement.where(ThreatRelevance.level == filters.relevance)
    if filters.published_after:
        statement = statement.where(ThreatEvent.published_at >= filters.published_after)
    if filters.published_before:
        statement = statement.where(ThreatEvent.published_at <= filters.published_before)

    count = session.scalar(
        select(func.count()).select_from(statement.order_by(None).subquery())
    ) or 0
    sort_columns = {
        "published_at": ThreatEvent.published_at,
        "updated_at": ThreatEvent.updated_at,
        "relevance": ThreatRelevance.score,
    }
    sort_column = sort_columns[filters.sort]
    ordering = sort_column.asc() if filters.direction == "asc" else sort_column.desc()
    statement = (
        statement.order_by(ordering, ThreatEvent.id.asc())
        .offset((filters.page - 1) * filters.limit)
        .limit(filters.limit)
    )
    rows = list(session.execute(statement))
    event_ids = [event.id for event, _, _ in rows]
    cves = {cve for event, _, _ in rows for cve in event.cves}
    signals = defaultdict(list)
    if cves:
        for signal in session.scalars(
            select(VulnerabilitySignal).where(VulnerabilitySignal.cve.in_(cves))
        ):
            signals[signal.cve].append(signal)
    cluster_map = defaultdict(list)
    if event_ids:
        cluster_rows = session.execute(
            select(ThreatClusterMembership, ThreatCluster)
            .join(ThreatCluster, ThreatCluster.id == ThreatClusterMembership.cluster_id)
            .where(ThreatClusterMembership.event_id.in_(event_ids))
        )
        for member, cluster in cluster_rows:
            cluster_map[member.event_id].append(
                {
                    "id": str(cluster.id),
                    "relationship_type": member.relationship_type,
                    "title": cluster.title,
                    "factors": member.factors,
                    "algorithm_version": cluster.algorithm_version,
                }
            )
    triage_map = {
        item.subject_id: item
        for item in session.scalars(
            select(RadarTriage).where(
                RadarTriage.workspace_id == workspace_id,
                RadarTriage.subject_type == "event",
                RadarTriage.subject_id.in_(event_ids),
            )
        )
    } if event_ids else {}
    link_map = defaultdict(list)
    if event_ids:
        for link in session.scalars(
            select(RadarReadinessLink).where(
                RadarReadinessLink.workspace_id == workspace_id,
                RadarReadinessLink.subject_type == "event",
                RadarReadinessLink.subject_id.in_(event_ids),
            )
        ):
            link_map[link.subject_id].append(link)

    return {
        "threshold": threshold,
        "total": count,
        "rows": rows,
        "signals": signals,
        "clusters": cluster_map,
        "triage": triage_map,
        "links": link_map,
    }
