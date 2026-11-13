from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import (
    ThreatCluster,
    ThreatClusterMembership,
    ThreatEvent,
)

ALGORITHM_VERSION = "deterministic-v1"


def normalized_title(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.casefold()).split())


def _key(kind: str, signal: str) -> str:
    digest = hashlib.sha256(f"{ALGORITHM_VERSION}:{kind}:{signal}".encode()).hexdigest()
    return f"{kind}:{digest}"


def _desired_clusters(events: list[ThreatEvent]) -> dict[str, dict]:
    exact: dict[tuple[str, tuple[str, ...]], list[ThreatEvent]] = defaultdict(list)
    related: dict[str, list[ThreatEvent]] = defaultdict(list)
    for event in events:
        cves = tuple(sorted({value.upper() for value in event.cves}))
        if cves:
            exact[(normalized_title(event.title), cves)].append(event)
            for cve in cves:
                related[cve].append(event)

    desired: dict[str, dict] = {}
    for (title, cves), members in exact.items():
        if len(members) < 2:
            continue
        signal = f"{title}|{','.join(cves)}"
        desired[_key("exact_duplicate", signal)] = {
            "relationship_type": "exact_duplicate",
            "title": members[0].title,
            "factors": ["normalized title match", f"identical CVE set: {', '.join(cves)}"],
            "members": members,
        }
    for cve, members in related.items():
        unique_sources = {event.source_id for event in members}
        if len(members) < 2 or len(unique_sources) < 2:
            continue
        desired[_key("related", cve)] = {
            "relationship_type": "related",
            "title": f"Related reporting for {cve}",
            "factors": [f"shared CVE: {cve}", "records originate from different sources"],
            "members": members,
        }
    return desired


def recompute_clusters(session: Session) -> dict[str, int]:
    events = list(session.scalars(select(ThreatEvent).order_by(ThreatEvent.id)))
    desired = _desired_clusters(events)
    existing = {
        cluster.key: cluster
        for cluster in session.scalars(
            select(ThreatCluster).where(ThreatCluster.algorithm_version == ALGORITHM_VERSION)
        )
    }

    memberships = 0
    for key, definition in desired.items():
        cluster = existing.get(key)
        if cluster is None:
            cluster = ThreatCluster(
                key=key,
                relationship_type=definition["relationship_type"],
                title=definition["title"],
                factors=definition["factors"],
                algorithm_version=ALGORITHM_VERSION,
            )
            session.add(cluster)
            session.flush()
        else:
            cluster.relationship_type = definition["relationship_type"]
            cluster.title = definition["title"]
            cluster.factors = definition["factors"]

        member_ids = {event.id for event in definition["members"]}
        session.execute(
            delete(ThreatClusterMembership).where(
                ThreatClusterMembership.cluster_id == cluster.id,
                ThreatClusterMembership.event_id.not_in(member_ids),
            )
        )
        current = {
            member.event_id: member
            for member in session.scalars(
                select(ThreatClusterMembership).where(
                    ThreatClusterMembership.cluster_id == cluster.id
                )
            )
        }
        for event in definition["members"]:
            member = current.get(event.id)
            if member is None:
                member = ThreatClusterMembership(cluster_id=cluster.id, event_id=event.id)
                session.add(member)
            member.relationship_type = definition["relationship_type"]
            member.factors = definition["factors"]
            memberships += 1

    obsolete = [cluster for key, cluster in existing.items() if key not in desired]
    for cluster in obsolete:
        session.delete(cluster)
    session.flush()
    return {"clusters": len(desired), "memberships": memberships}
