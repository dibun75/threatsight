"""Load the labelled synthetic Nordic Retail reference through application code.

Requires --synthetic-reference. Refuses every other database name. Does not
print connection details, credentials, or source payloads.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatsight_api.analysis.execute import execute as analyze
from threatsight_api.connectors.junos.fixtures import configuration as junos_configuration
from threatsight_api.connectors.meraki.fixtures import configuration as meraki_configuration
from threatsight_api.connectors.microsoft.fixtures import azure_configuration, entra_configuration
from threatsight_api.connectors.microsoft.registry import accepted_instance
from threatsight_api.correlation.execute import add_alias, execute as correlate
from threatsight_api.correlation.fixture import reference_events
from threatsight_api.graph.materialize import materialize
from threatsight_api.persistence.models import (
    ConnectorInstance,
    CorrelationMatch,
    GraphNode,
    GraphSnapshot,
    OrganizationProfile,
    RunnerRegistration,
    ThreatCluster,
    ThreatClusterMembership,
    ThreatEvent,
    ThreatRelevance,
    ThreatSource,
    VulnerabilitySignal,
    Workspace,
)
from threatsight_api.persistence.session import get_engine
from threatsight_api.radar.relevance import score_relevance
from threatsight_api.services.audit import record_audit

ACTOR = "synthetic-reference"
RUNNER_NAME = "synthetic-reference-runner"
GRAPH_KEY = "synthetic-nordic-graph"
ANALYSIS_KEY = "synthetic-nordic-analysis"
CORRELATION_KEY = "synthetic-nordic-correlation"
CONNECTORS = (
    ("azure.resource_graph", "Synthetic Azure reference", azure_configuration),
    ("entra.identity", "Synthetic Entra reference", entra_configuration),
    ("meraki.dashboard", "Synthetic Meraki reference", meraki_configuration),
    ("junos.device", "Synthetic Junos reference", junos_configuration),
)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--synthetic-reference", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if not args.synthetic_reference:
        raise SystemExit("refusing without --synthetic-reference")
    name = _database_name()
    if name != "threatsight" and not name.startswith("threatsight_"):
        raise SystemExit("refusing an unrecognized database")
    engine = get_engine()
    with Session(engine) as db:
        workspace = db.scalar(select(Workspace).where(Workspace.key == "default", Workspace.status == "active"))
        if workspace is None:
            raise SystemExit("default workspace is missing")
        if args.dry_run:
            _print_counts(db, workspace.id, "dry-run")
            return
        _load(db, workspace)
        db.commit()
        _print_counts(db, workspace.id, "loaded")


def _database_name() -> str:
    url = os.environ.get("THREATSIGHT_DATABASE_URL", "")
    return url.rsplit("/", 1)[-1].split("?", 1)[0]


def _load(db: Session, workspace: Workspace) -> None:
    runner = db.scalar(select(RunnerRegistration).where(
        RunnerRegistration.workspace_id == workspace.id,
        RunnerRegistration.name == RUNNER_NAME,
    ))
    if runner is None:
        runner = RunnerRegistration(
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
            name=RUNNER_NAME,
            status="disconnected",
            capabilities=["fixture"],
        )
        db.add(runner)
        db.flush()
    now = datetime.now(UTC)
    for key, label, configuration in CONNECTORS:
        existing = db.scalar(select(ConnectorInstance).where(
            ConnectorInstance.workspace_id == workspace.id,
            ConnectorInstance.name == label,
        ))
        if existing is not None:
            if existing.maturity == "live_verified":
                raise SystemExit("refusing to relabel a live-verified connector")
            continue
        maturity, parsed = accepted_instance(
            connector_key=key,
            mode="fixture",
            maturity="fixture_tested",
            configuration=configuration(),
            runner_id=runner.id,
            secret_reference_id=None,
        )
        if maturity != "fixture_tested":
            raise SystemExit("fixture configuration did not stay fixture_tested")
        db.add(ConnectorInstance(
            tenant_id=workspace.tenant_id,
            workspace_id=workspace.id,
            runner_id=runner.id,
            connector_key=key,
            name=label,
            mode="fixture",
            maturity=maturity,
            status="enabled",
            configuration=parsed,
            health_state="unknown",
            health_detail="Live connection not validated",
            last_health_at=now,
        ))
    db.flush()
    source = db.scalar(select(ThreatSource).where(ThreatSource.key == "synthetic-correlation"))
    if source is None:
        source = ThreatSource(
            key="synthetic-correlation",
            provider="Synthetic",
            authority="Test",
            locator="https://example.test/correlation",
        )
        db.add(source)
        db.flush()
    created: list[ThreatEvent] = []
    clusters: dict[str, ThreatCluster] = {}
    for item in reference_events():
        external = f"000-correlation-{item['event_id']}"
        if db.scalar(select(ThreatEvent.id).where(ThreatEvent.external_id == external)):
            continue
        event = ThreatEvent(
            source_id=source.id,
            external_id=external,
            event_type="advisory",
            title=item["cves"][0],
            summary="synthetic",
            canonical_url="https://example.test/advisory",
            content_hash=hashlib.sha256(external.encode()).hexdigest(),
            cves=item["cves"],
            vendors=item["vendors"],
            products=item["products"],
            authority_jurisdictions=item["authority_jurisdictions"],
            target_countries=item["target_countries"],
            exploitation_status=item["exploitation_status"],
            limitations=["stale_source"] if item["freshness"] == "stale" else [],
            attributes={
                "cpes": item["cpes"],
                "version_ranges": item["version_ranges"],
                "purls": item["purls"],
                "cloud_service": item["cloud_service"],
                "cloud_scope": item["cloud_scope"],
                "origin": "synthetic",
            },
            source_payload_hash=hashlib.sha256(external.encode()).hexdigest(),
            parser_version="p2-13.v1",
        )
        db.add(event)
        db.flush()
        created.append(event)
        if item["cluster_key"]:
            cluster_key = f"{item['cluster_key']}-synthetic"
            cluster = clusters.get(cluster_key)
            if cluster is None:
                cluster = db.scalar(select(ThreatCluster).where(ThreatCluster.key == cluster_key))
            if cluster is None:
                cluster = ThreatCluster(
                    key=cluster_key,
                    relationship_type="duplicate",
                    title=item["cluster_key"],
                    factors=["cve"],
                    algorithm_version="p2-13.v1",
                )
                db.add(cluster)
                db.flush()
            clusters[cluster_key] = cluster
            linked = db.scalar(select(ThreatClusterMembership.id).where(
                ThreatClusterMembership.cluster_id == cluster.id,
                ThreatClusterMembership.event_id == event.id,
            ))
            if linked is None:
                db.add(ThreatClusterMembership(
                    cluster_id=cluster.id,
                    event_id=event.id,
                    relationship_type="duplicate",
                    factors=["cve"],
                ))
    profile = db.scalar(select(OrganizationProfile).where(OrganizationProfile.workspace_id == workspace.id))
    signals = {item.cve: item.epss_score for item in db.scalars(select(VulnerabilitySignal))}
    if profile is not None:
        for event in created:
            result = score_relevance(profile, event, [signals[cve] for cve in event.cves if cve in signals])
            db.add(ThreatRelevance(
                workspace_id=workspace.id,
                event_id=event.id,
                score=result.score,
                level=result.level,
                reasons=result.reasons,
                matches=result.matches,
                assessed_at=now,
            ))
    snapshot = materialize(
        db,
        tenant_id=workspace.tenant_id,
        workspace_id=workspace.id,
        actor=ACTOR,
        idempotency_key=GRAPH_KEY,
        fixture="correlation",
    )
    add_alias(
        db,
        tenant_id=workspace.tenant_id,
        workspace_id=workspace.id,
        actor=ACTOR,
        alias_vendor="acme",
        alias_product="synth-widget",
        vendor="acme",
        product="widget",
        reason="Approved synthetic alias",
    )
    correlate(
        db,
        tenant_id=workspace.tenant_id,
        workspace_id=workspace.id,
        snapshot_id=snapshot.id,
        actor=ACTOR,
        idempotency_key=CORRELATION_KEY,
    )
    analyze(
        db,
        tenant_id=workspace.tenant_id,
        workspace_id=workspace.id,
        snapshot_id=snapshot.id,
        actor=ACTOR,
        idempotency_key=ANALYSIS_KEY,
    )
    record_audit(
        db,
        entity_type="workspace",
        entity_id=workspace.id,
        action="create",
        actor=ACTOR,
        payload={"reference": "synthetic-nordic-retail", "maturity": "fixture_tested"},
    )


def _print_counts(db: Session, workspace_id: uuid.UUID, label: str) -> None:
    snapshot = db.scalar(select(GraphSnapshot).where(
        GraphSnapshot.workspace_id == workspace_id,
        GraphSnapshot.idempotency_key == GRAPH_KEY,
        GraphSnapshot.status == "completed",
    ))
    nodes = 0 if snapshot is None else db.scalar(select(func.count()).select_from(GraphNode).where(GraphNode.snapshot_id == snapshot.id))
    matches = db.scalar(select(func.count()).select_from(CorrelationMatch).where(CorrelationMatch.workspace_id == workspace_id)) or 0
    instances = db.scalar(select(func.count()).select_from(ConnectorInstance).where(
        ConnectorInstance.workspace_id == workspace_id,
        ConnectorInstance.maturity == "fixture_tested",
    )) or 0
    live = db.scalar(select(func.count()).select_from(ConnectorInstance).where(
        ConnectorInstance.workspace_id == workspace_id,
        ConnectorInstance.maturity == "live_verified",
    )) or 0
    print(f"{label} synthetic reference nodes={nodes} matches={matches} fixture_instances={instances} live_verified={live}")


if __name__ == "__main__":
    main()
