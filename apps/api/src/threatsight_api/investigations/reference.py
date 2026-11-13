"""Idempotent synthetic reference journeys. Removable by source key."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import text

CHAINS = (
    {
        "chain": "customer-ordering",
        "service": "synthetic.fixture:service:customer-ordering",
        "asset": "synthetic.fixture:device:exact-widget",
        "cve": "CVE-2024-1001",
        "edge": "synthetic.fixture:edge:customer-ordering-widget",
        "rule": "reference-ordering-chain-v1",
        "consequence": "Online ordering could be interrupted, delaying customer purchases and fulfilment.",
        "decision": "Validate the installed version and assign an owner.",
        "control": "Validate the installed version",
        "action": "Assign an owner to confirm the installed version",
        "evidence_key": "synthetic-reference:customer-ordering:version",
        "evidence_title": "Installed version is not observed",
        "evidence_body": "ordering-widget has an identifier match. The installed version still needs validation. This does not prove exploitation or packet delivery.",
        "explanation": "ordering-widget is a configured dependency of Customer ordering. This is not packet delivery.",
    },
    {
        "chain": "privileged-administration",
        "service": "synthetic.fixture:service:privileged-administration",
        "asset": "meraki.dashboard:device:meraki-ap",
        "cve": "CVE-2024-2001",
        "edge": "synthetic.fixture:edge:privileged-admin-gateway",
        "rule": "reference-privileged-chain-v1",
        "consequence": "Administration of the synthetic environment could be changed by an unreviewed privileged assignment.",
        "decision": "Validate the recorded firmware and the privileged assignment. Effective privilege is unknown.",
        "control": "Review privileged group membership",
        "action": "Assign an owner to validate the privileged assignment",
        "evidence_key": "synthetic-reference:privileged-administration:membership",
        "evidence_title": "Privileged assignment is not observed",
        "evidence_body": "privileged-access-gateway has a version-supported candidate. Effective privilege is unknown. This does not prove access or that authentication was effective.",
        "explanation": "privileged-access-gateway is a configured member of Privileged administration. Effective privilege is unknown.",
    },
    {
        "chain": "remote-access",
        "service": "synthetic.fixture:service:remote-access",
        "asset": "junos.device:device:junos-edge",
        "cve": "CVE-2024-3001",
        "edge": "synthetic.fixture:edge:remote-access-vpn",
        "rule": "reference-remote-chain-v1",
        "consequence": "Site connectivity could be interrupted if the recorded edge software is affected.",
        "decision": "Validate the recorded software version. Observed reachability is unknown.",
        "control": "Review the remote-access peer configuration",
        "action": "Assign an owner to validate the remote-access configuration",
        "evidence_key": "synthetic-reference:remote-access:peer",
        "evidence_title": "Remote-access reachability is unknown",
        "evidence_body": "remote-access-vpn-oslo records software 23.4R1-synth. Observed reachability is unknown. This does not prove exposure or that the peer is blocked.",
        "explanation": "remote-access-vpn-oslo is a configured member of Remote access. Observed reachability is unknown.",
    },
)


def install(connection) -> None:
    now = datetime.now(UTC)
    for chain in CHAINS:
        services = connection.execute(
            text(
                """
                SELECT service.tenant_id, service.workspace_id, service.snapshot_id, service.id AS service_id, asset.id AS asset_id
                FROM graph_nodes AS service
                JOIN graph_nodes AS asset
                  ON asset.snapshot_id = service.snapshot_id
                 AND asset.source_key = :asset
                WHERE service.source_key = :service
                  AND service.snapshot_id IN (SELECT id FROM graph_snapshots WHERE is_current)
                """
            ),
            {"asset": chain["asset"], "service": chain["service"]},
        ).mappings()
        for row in services:
            edge_id = connection.execute(
                text(
                    """
                    INSERT INTO graph_edges (
                        id, tenant_id, workspace_id, snapshot_id, edge_type, source_key, from_node_id, to_node_id,
                        maturity, evidence_mode, connector_key, source_contract, source_record_id, collected_at,
                        materialized_at, freshness, confidence, limitations, lifecycle, contributing
                    ) VALUES (
                        :id, :tenant_id, :workspace_id, :snapshot_id, 'depends_on', :source_key, :from_id, :to_id,
                        'fixture_tested', 'configured', 'synthetic-fixture', 'reference-journey-v1', :source_key,
                        :now, :now, 'fresh', 'stated', CAST(:limitations AS jsonb), 'active', '[]'::jsonb
                    )
                    ON CONFLICT (snapshot_id, source_key) DO UPDATE SET evidence_mode = 'configured'
                    RETURNING id
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": row["tenant_id"],
                    "workspace_id": row["workspace_id"],
                    "snapshot_id": row["snapshot_id"],
                    "source_key": chain["edge"],
                    "from_id": row["asset_id"],
                    "to_id": row["service_id"],
                    "now": now,
                    "limitations": '["synthetic_reference","not_packet_delivery"]',
                },
            ).scalar_one()
            run_id = connection.execute(
                text(
                    """
                    SELECT id FROM analysis_runs
                    WHERE workspace_id = :workspace AND snapshot_id = :snapshot AND is_current
                    LIMIT 1
                    """
                ),
                {"workspace": row["workspace_id"], "snapshot": row["snapshot_id"]},
            ).scalar()
            match = connection.execute(
                text(
                    """
                    SELECT match.id
                    FROM correlation_matches AS match
                    JOIN correlation_runs AS run ON run.id = match.run_id
                    WHERE run.is_current AND match.cve = :cve AND match.asset_key = :asset
                    LIMIT 1
                    """
                ),
                {"cve": chain["cve"], "asset": chain["asset"]},
            ).scalar()
            if run_id is not None:
                exists = connection.execute(
                    text("SELECT id FROM analysis_results WHERE rule_id = :rule AND snapshot_id = :snapshot"),
                    {"rule": chain["rule"], "snapshot": row["snapshot_id"]},
                ).scalar()
                if exists is None:
                    connection.execute(
                        text(
                            """
                            INSERT INTO analysis_results (
                                id, tenant_id, workspace_id, snapshot_id, run_id, rule_id, rule_version, category, state,
                                service_key, node_keys, edge_keys, evidence_modes, maturity, freshness, limitations,
                                missing_facts, explanation, created_at
                            ) VALUES (
                                :id, :tenant_id, :workspace_id, :snapshot_id, :run_id, :rule, 'v1', 'cross_domain_service_path',
                                'supported_candidate', :service, CAST(:nodes AS jsonb), CAST(:edges AS jsonb),
                                '["configured"]'::jsonb, 'fixture_tested', 'fresh', CAST(:limitations AS jsonb), '[]'::jsonb,
                                :explanation, :now
                            )
                            """
                        ),
                        {
                            "id": str(uuid.uuid4()),
                            "tenant_id": row["tenant_id"],
                            "workspace_id": row["workspace_id"],
                            "snapshot_id": row["snapshot_id"],
                            "run_id": run_id,
                            "rule": chain["rule"],
                            "service": chain["service"],
                            "nodes": json.dumps([chain["asset"], chain["service"]]),
                            "edges": json.dumps([chain["edge"]]),
                            "limitations": '["synthetic_reference","not_control_effectiveness","not_packet_delivery"]',
                            "explanation": chain["explanation"],
                            "now": now,
                    },
                )
            _evidence(connection, row, chain, now)
            connection.execute(
                text(
                    """
                    INSERT INTO reference_journeys (
                        id, workspace_id, chain_key, service_source_key, match_id, edge_id, consequence, decision_text,
                        control_title, evidence_status, action_title, owner_state, deadline_state, maturity
                    ) VALUES (
                        :id, :workspace_id, :chain, :service, :match_id, :edge_id,
                        :consequence, :decision, :control, 'gap',
                        :action, 'not_assigned', 'not_recorded', 'fixture_tested'
                    )
                    ON CONFLICT (workspace_id, chain_key) DO UPDATE
                      SET edge_id = EXCLUDED.edge_id,
                          match_id = EXCLUDED.match_id,
                          consequence = EXCLUDED.consequence,
                          decision_text = EXCLUDED.decision_text,
                          control_title = EXCLUDED.control_title,
                          action_title = EXCLUDED.action_title
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "workspace_id": row["workspace_id"],
                    "chain": chain["chain"],
                    "service": chain["service"],
                    "match_id": match,
                    "edge_id": edge_id,
                    "consequence": chain["consequence"],
                    "decision": chain["decision"],
                    "control": chain["control"],
                    "action": chain["action"],
                },
            )


def _evidence(connection, row, chain: dict, now: datetime) -> None:
    linked = connection.execute(
        text(
            """
            SELECT evidence_id FROM reference_evidence_links
            WHERE workspace_id = :workspace AND evidence_key = :key
            """
        ),
        {"workspace": row["workspace_id"], "key": chain["evidence_key"]},
    ).scalar()
    if linked is not None:
        return
    evidence_id = str(uuid.uuid4())
    connection.execute(
        text(
            """
            INSERT INTO evidence_records (
                id, title, description, evidence_type, source_reference, provenance, collected_at, owner, status
            ) VALUES (
                :id, :title, :body, 'manual', :key,
                'Synthetic reference. Configured, not observed.', :now, 'Unassigned', 'accepted'
            )
            """
        ),
        {"id": evidence_id, "title": chain["evidence_title"], "body": chain["evidence_body"], "key": chain["evidence_key"], "now": now},
    )
    connection.execute(
        text(
            """
            INSERT INTO reference_evidence_links (
                id, workspace_id, service_source_key, evidence_key, evidence_id, relationship
            ) VALUES (
                :id, :workspace, :service, :key, :evidence_id, 'control'
            )
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "workspace": row["workspace_id"],
            "service": chain["service"],
            "key": chain["evidence_key"],
            "evidence_id": evidence_id,
        },
    )


def json_list(values: list[str]) -> str:
    return json.dumps(values)
