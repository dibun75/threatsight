from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from threatsight_api.db import _alembic_root
from threatsight_api.graph.vocabulary import EDGE_TYPES, NODE_TYPES
from threatsight_api.test_database import assert_isolated_name, drop_isolated_database, provision_isolated_database

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
pytestmark = pytest.mark.skipif(not LIVE, reason="requires postgres")


def test_graph_migration_matches_vocabulary_and_downgrades_only_graph_tables() -> None:
    revision = (_alembic_root() / "alembic/versions/0014_exposure_graph.py").read_text()
    for item in (*NODE_TYPES, *EDGE_TYPES):
        assert f"'{item}'" in revision
    analysis = (_alembic_root() / "alembic/versions/0015_exposure_analysis.py").read_text()
    assert "0014_exposure_graph" in analysis
    assert "analysis_runs" in analysis
    base = os.environ["THREATSIGHT_DATABASE_URL"]
    name, url = provision_isolated_database(base)
    assert_isolated_name(name)
    engine = create_engine(url, pool_pre_ping=True)
    root = _alembic_root()
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    try:
        command.upgrade(cfg, "head")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0028_multisource_intelligence"
            assert connection.scalar(text("SELECT to_regclass('intelligence_clusters')")) == "intelligence_clusters"
            assert connection.scalar(text("SELECT to_regclass('evidence_signatures')")) == "evidence_signatures"
            assert connection.scalar(text("SELECT to_regclass('readiness_actions')")) == "readiness_actions"
            assert connection.scalar(text("SELECT to_regclass('readiness_triggers')")) == "readiness_triggers"
            assert connection.scalar(text("SELECT to_regclass('reference_evidence_links')")) == "reference_evidence_links"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0027_verifiable_evidence"
            assert connection.scalar(text("SELECT to_regclass('intelligence_clusters')")) is None
            assert connection.scalar(text("SELECT to_regclass('evidence_signatures')")) == "evidence_signatures"
            assert connection.scalar(text("SELECT to_regclass('readiness_actions')")) == "readiness_actions"
            assert connection.scalar(text("SELECT to_regclass('readiness_triggers')")) == "readiness_triggers"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0026_accountable_closure"
            assert connection.scalar(text("SELECT to_regclass('evidence_signatures')")) is None
            assert connection.scalar(text("SELECT to_regclass('readiness_actions')")) == "readiness_actions"
            assert connection.scalar(text("SELECT to_regclass('readiness_triggers')")) == "readiness_triggers"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0025_continuous_readiness"
            assert connection.scalar(text("SELECT to_regclass('readiness_actions')")) is None
            assert connection.scalar(text("SELECT to_regclass('readiness_triggers')")) == "readiness_triggers"
            assert connection.scalar(text("SELECT to_regclass('reference_evidence_links')")) == "reference_evidence_links"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0024_reference_evidence"
            assert connection.scalar(text("SELECT to_regclass('readiness_triggers')")) is None
            assert connection.scalar(text("SELECT to_regclass('reference_evidence_links')")) == "reference_evidence_links"
            assert connection.scalar(text("SELECT to_regclass('reference_journeys')")) == "reference_journeys"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0023_reference_journeys"
            assert connection.scalar(text("SELECT to_regclass('reference_evidence_links')")) is None
            assert connection.scalar(text("SELECT to_regclass('reference_journeys')")) == "reference_journeys"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0022_radar_collection"
            assert connection.scalar(text("SELECT to_regclass('telemetry_runs')")) == "telemetry_runs"
            assert connection.scalar(text("SELECT count(*) FROM reference_journeys WHERE chain_key = 'remote-access'")) == 0
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0021_telemetry_journey"
            assert connection.scalar(text("SELECT to_regclass('telemetry_runs')")) is None
            assert connection.scalar(text("SELECT to_regclass('telemetry_snapshots')")) == "telemetry_snapshots"
            assert connection.scalar(text("SELECT to_regclass('reference_journeys')")) == "reference_journeys"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0020_local_auth"
            assert connection.scalar(text("SELECT to_regclass('telemetry_snapshots')")) is None
            assert connection.scalar(text("SELECT to_regclass('local_credentials')")) == "local_credentials"
            assert connection.scalar(text("SELECT to_regclass('landscape_collection_runs')")) == "landscape_collection_runs"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0019_intelligence_runs"
            assert connection.scalar(text("SELECT to_regclass('local_credentials')")) is None
            assert connection.scalar(text("SELECT to_regclass('identities')")) == "identities"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0018_threat_landscape"
            assert connection.scalar(text("SELECT to_regclass('landscape_collection_runs')")) is None
            assert connection.scalar(text("SELECT to_regclass('landscape_advisories')")) == "landscape_advisories"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0017_public_demo"
            assert connection.scalar(text("SELECT to_regclass('landscape_advisories')")) is None
            assert connection.scalar(text("SELECT to_regclass('correlation_runs')")) == "correlation_runs"
            assert connection.scalar(text("SELECT to_regclass('analysis_runs')")) == "analysis_runs"
            assert connection.scalar(text("SELECT to_regclass('graph_snapshots')")) == "graph_snapshots"
            assert connection.scalar(text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = 'workspaces' AND column_name = 'classification'"
            )) == 1
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0016_threat_correlation"
            assert connection.scalar(text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = 'workspaces' AND column_name = 'classification'"
            )) is None
            assert connection.scalar(text("SELECT to_regclass('correlation_runs')")) == "correlation_runs"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0015_exposure_analysis"
            assert connection.scalar(text("SELECT to_regclass('correlation_runs')")) is None
            assert connection.scalar(text("SELECT to_regclass('analysis_runs')")) == "analysis_runs"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0014_exposure_graph"
            assert connection.scalar(text("SELECT to_regclass('analysis_runs')")) is None
            assert connection.scalar(text("SELECT to_regclass('graph_snapshots')")) == "graph_snapshots"
        command.downgrade(cfg, "-1")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0013_connector_execution"
            assert connection.scalar(text("SELECT to_regclass('graph_snapshots')")) is None
            assert connection.scalar(text("SELECT to_regclass('threat_events')")) == "threat_events"
        command.upgrade(cfg, "head")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT to_regclass('correlation_matches')")) == "correlation_matches"
            assert connection.scalar(text("SELECT to_regclass('analysis_results')")) == "analysis_results"
            assert connection.scalar(text("SELECT to_regclass('graph_service_memberships')")) == "graph_service_memberships"
    finally:
        engine.dispose()
        drop_isolated_database(base, name)
