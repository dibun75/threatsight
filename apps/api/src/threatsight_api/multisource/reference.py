"""Idempotent Warehouse automation synthetic OT reference journey."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import text

SERVICE_KEY = "synthetic.fixture:service:warehouse-automation"
ASSET_KEY = "synthetic.fixture:device:simatic-iot2050-advanced"
EDGE_KEY = "synthetic.fixture:edge:warehouse-iot2050"
CVE = "CVE-2026-58115"
MODEL = "6ES7647-0BA00-1YA2"
TRIGGER_KEY = "warehouse-ot-cve-2026-58115"
REC_KEY = "warehouse-ot-verify-iot2050-node-red"


def install(connection) -> None:
    now = datetime.now(UTC)
    snapshots = connection.execute(
        text("SELECT id, tenant_id, workspace_id FROM graph_snapshots WHERE is_current")
    ).mappings()
    for snap in snapshots:
        service_id = connection.execute(
            text(
                """
                INSERT INTO graph_nodes (
                    id, tenant_id, workspace_id, snapshot_id, node_type, source_key, vendor_id, label,
                    maturity, evidence_mode, connector_key, source_contract, source_record_id,
                    collected_at, materialized_at, freshness, confidence, limitations, lifecycle, attributes
                ) VALUES (
                    :id, :tenant_id, :workspace_id, :snapshot_id, 'business_service', :source_key,
                    'service:warehouse-automation', 'Warehouse automation',
                    'fixture_tested', 'configured', 'synthetic-fixture', 'warehouse-ot-v1', :source_key,
                    :now, :now, 'fresh', 'stated', CAST(:limitations AS jsonb), 'active', CAST(:attributes AS jsonb)
                )
                ON CONFLICT (snapshot_id, source_key) DO UPDATE
                  SET label = EXCLUDED.label, attributes = EXCLUDED.attributes, limitations = EXCLUDED.limitations
                RETURNING id
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "tenant_id": snap["tenant_id"],
                "workspace_id": snap["workspace_id"],
                "snapshot_id": snap["id"],
                "source_key": SERVICE_KEY,
                "now": now,
                "limitations": json.dumps(
                    ["synthetic_reference_only", "not_a_live_customer_environment", "does_not_claim_attack_or_compromise"]
                ),
                "attributes": json.dumps({"synthetic": True, "domain": "ot_warehouse"}),
            },
        ).scalar_one()
        asset_id = connection.execute(
            text(
                """
                INSERT INTO graph_nodes (
                    id, tenant_id, workspace_id, snapshot_id, node_type, source_key, vendor_id, label,
                    maturity, evidence_mode, connector_key, source_contract, source_record_id,
                    collected_at, materialized_at, freshness, confidence, limitations, lifecycle, attributes
                ) VALUES (
                    :id, :tenant_id, :workspace_id, :snapshot_id, 'device', :source_key,
                    :vendor_id, 'SIMATIC IoT2050 Advanced',
                    'fixture_tested', 'configured', 'synthetic-fixture', 'warehouse-ot-v1', :source_key,
                    :now, :now, 'fresh', 'stated', CAST(:limitations AS jsonb), 'active', CAST(:attributes AS jsonb)
                )
                ON CONFLICT (snapshot_id, source_key) DO UPDATE
                  SET attributes = EXCLUDED.attributes, limitations = EXCLUDED.limitations
                RETURNING id
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "tenant_id": snap["tenant_id"],
                "workspace_id": snap["workspace_id"],
                "snapshot_id": snap["id"],
                "source_key": ASSET_KEY,
                "vendor_id": f"siemens:simatic-iot2050-advanced:{MODEL}",
                "now": now,
                "limitations": json.dumps(
                    [
                        "industrial_os_version_unknown",
                        "node_red_installation_unknown",
                        "node_red_authentication_unknown",
                        "internet_reachability_unknown",
                        "synthetic_reference_only",
                    ]
                ),
                "attributes": json.dumps(
                    {
                        "vendor": "Siemens",
                        "product": "SIMATIC IoT2050 Advanced",
                        "model_number": MODEL,
                        "industrial_os_version": "unknown",
                        "node_red_installed": "unknown",
                        "node_red_authentication": "unknown",
                        "internet_reachability": "unknown",
                        "synthetic": True,
                    }
                ),
            },
        ).scalar_one()
        connection.execute(
            text(
                """
                INSERT INTO graph_edges (
                    id, tenant_id, workspace_id, snapshot_id, edge_type, source_key, from_node_id, to_node_id,
                    maturity, evidence_mode, connector_key, source_contract, source_record_id, collected_at,
                    materialized_at, freshness, confidence, limitations, lifecycle, contributing
                ) VALUES (
                    :id, :tenant_id, :workspace_id, :snapshot_id, 'depends_on', :source_key, :from_id, :to_id,
                    'fixture_tested', 'configured', 'synthetic-fixture', 'warehouse-ot-v1', :source_key,
                    :now, :now, 'fresh', 'stated', CAST(:limitations AS jsonb), 'active', '[]'::jsonb
                )
                ON CONFLICT (snapshot_id, source_key) DO UPDATE SET evidence_mode = 'configured'
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "tenant_id": snap["tenant_id"],
                "workspace_id": snap["workspace_id"],
                "snapshot_id": snap["id"],
                "source_key": EDGE_KEY,
                "from_id": asset_id,
                "to_id": service_id,
                "now": now,
                "limitations": json.dumps(["configured_dependency_not_observed_traffic", "synthetic_reference"]),
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO graph_service_memberships (
                    id, tenant_id, workspace_id, snapshot_id, service_node_id, member_node_id, role,
                    evidence_mode, maturity, derivation_rule, limitations, actor, scoped_at
                ) VALUES (
                    :id, :tenant_id, :workspace_id, :snapshot_id, :service_id, :member_id, 'dependency',
                    'configured', 'fixture_tested', 'warehouse-ot-v1', CAST(:limitations AS jsonb),
                    'synthetic-reference', :now
                )
                ON CONFLICT (snapshot_id, service_node_id, member_node_id, role) DO NOTHING
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "tenant_id": snap["tenant_id"],
                "workspace_id": snap["workspace_id"],
                "snapshot_id": snap["id"],
                "service_id": service_id,
                "member_id": asset_id,
                "now": now,
                "limitations": json.dumps(["synthetic_reference_only"]),
            },
        )
        _seed_fixture_cluster(connection, now)
        _ensure_readiness(connection, snap, service_id, asset_id, now)


def _seed_fixture_cluster(connection, now: datetime) -> None:
    doc_id = connection.execute(
        text(
            """
            INSERT INTO intelligence_source_documents (
                id, source_key, source_role, external_id, canonical_url, title, published_at, source_updated_at,
                content_hash, metadata_safe, maturity, correction_state, parser_version
            ) VALUES (
                :id, 'siemens-productcert', 'vendor_authority', 'SSA-834709-fixture',
                'https://cert-portal.siemens.com/productcert/csaf/ssa-834709.json',
                'SSA-834709 fixture reference (not live_verified)',
                :now, :now, :hash, CAST(:meta AS jsonb), 'fixture_tested', 'current', 'multisource-v1'
            )
            ON CONFLICT (source_key, external_id) DO UPDATE SET last_collected_at = now()
            RETURNING id
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "now": now,
            "hash": "fixture-ssa-834709",
            "meta": json.dumps({"ssa_id": "SSA-834709", "cves": [CVE], "attribution": "Siemens ProductCERT CSAF", "fixture": True}),
        },
    ).scalar_one()
    connection.execute(
        text(
            """
            INSERT INTO intelligence_assertions (
                id, document_id, subject_key, assertion_type, value, observed_at, effective_at,
                source_role, parser_version, provenance, limitations
            )
            SELECT CAST(:id AS uuid), CAST(:doc AS uuid), CAST(:cve AS varchar), 'product_affected',
                   CAST(:value AS jsonb), CAST(:now AS timestamptz), CAST(:now AS timestamptz),
                   'vendor_authority', 'multisource-v1', CAST(:prov AS jsonb), CAST(:lim AS jsonb)
            WHERE NOT EXISTS (
                SELECT 1 FROM intelligence_assertions
                 WHERE document_id = CAST(:doc AS uuid)
                   AND assertion_type = 'product_affected'
                   AND subject_key = CAST(:cve AS varchar)
            )
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "doc": doc_id,
            "cve": CVE,
            "now": now,
            "value": json.dumps(
                {"product_name": "SIMATIC IoT2050 Advanced (6ES7647-0BA00-1YA2)", "model_numbers": [MODEL], "vendor": "Siemens"}
            ),
            "prov": json.dumps({"source_key": "siemens-productcert", "fixture": True}),
            "lim": json.dumps(["fixture_reference_only"]),
        },
    )
    for assertion_type, value in (
        ("prerequisite_required", {"prerequisite": "node_red_installed"}),
        ("version_affected", {"expression": "vers:intdot/<4.3.4.1"}),
        ("fixed_version", {"details": "Update to V4.3.4.1 or later version"}),
        ("vendor_vulnerability_confirmed", {"ssa_id": "SSA-834709"}),
    ):
        connection.execute(
            text(
                """
                INSERT INTO intelligence_assertions (
                    id, document_id, subject_key, assertion_type, value, observed_at, effective_at,
                    source_role, parser_version, provenance, limitations
                )
                SELECT CAST(:id AS uuid), CAST(:doc AS uuid), CAST(:cve AS varchar), CAST(:atype AS varchar),
                       CAST(:value AS jsonb), CAST(:now AS timestamptz), CAST(:now AS timestamptz),
                       'vendor_authority', 'multisource-v1', CAST(:prov AS jsonb), CAST(:lim AS jsonb)
                WHERE NOT EXISTS (
                    SELECT 1 FROM intelligence_assertions
                     WHERE document_id = CAST(:doc AS uuid)
                       AND assertion_type = CAST(:atype AS varchar)
                       AND subject_key = CAST(:cve AS varchar)
                )
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "doc": doc_id,
                "cve": CVE,
                "atype": assertion_type,
                "now": now,
                "value": json.dumps(value),
                "prov": json.dumps({"source_key": "siemens-productcert", "fixture": True}),
                "lim": json.dumps(["fixture_reference_only"]),
            },
        )
    cluster_id = connection.execute(
        text(
            """
            INSERT INTO intelligence_clusters (
                id, primary_key_type, primary_key_value, title, exploitation_state, exploitation_explanation, aliases, maturity
            ) VALUES (
                :id, 'cve', :cve, :title, 'not_reported',
                'Vendor advisory fixture present; live exploitation observations are collected separately.',
                CAST(:aliases AS jsonb), 'fixture_tested'
            )
            ON CONFLICT (primary_key_type, primary_key_value) DO UPDATE SET title = EXCLUDED.title
            RETURNING id
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "cve": CVE,
            "title": f"{CVE} Siemens SIMATIC IoT2050 Advanced",
            "aliases": json.dumps({"ssa": ["SSA-834709"], "models": [MODEL]}),
        },
    ).scalar_one()
    connection.execute(
        text(
            """
            INSERT INTO intelligence_cluster_documents (id, cluster_id, document_id)
            VALUES (:id, :cluster, :doc)
            ON CONFLICT (cluster_id, document_id) DO NOTHING
            """
        ),
        {"id": str(uuid.uuid4()), "cluster": cluster_id, "doc": doc_id},
    )


def _ensure_readiness(connection, snap, service_id, asset_id, now: datetime) -> None:
    trigger_id = connection.execute(
        text(
            """
            INSERT INTO readiness_triggers (
                id, tenant_id, workspace_id, external_key, reason_code, summary, service_source_key,
                service_node_id, snapshot_id, evidence_hash, maturity, status, provenance
            ) VALUES (
                :id, :tenant_id, :workspace_id, :external_key, 'emerging_exploitation',
                'Validate Warehouse automation SIMATIC IoT2050 Advanced for CVE-2026-58115',
                :service_key, :service_id, :snapshot_id, :hash, 'fixture_tested', 'open', CAST(:prov AS jsonb)
            )
            ON CONFLICT (workspace_id, external_key) DO UPDATE SET summary = EXCLUDED.summary
            RETURNING id
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "tenant_id": snap["tenant_id"],
            "workspace_id": snap["workspace_id"],
            "external_key": TRIGGER_KEY,
            "service_key": SERVICE_KEY,
            "service_id": service_id,
            "snapshot_id": snap["id"],
            "hash": "warehouse-ot-cve-2026-58115",
            "prov": json.dumps({"cve": CVE, "synthetic": True}),
        },
    ).scalar_one()
    connection.execute(
        text(
            """
            INSERT INTO readiness_recommendations (
                id, tenant_id, workspace_id, trigger_id, external_key, state, service_source_key, service_node_id,
                asset_source_key, asset_node_id, control_title, check_id, check_version, match_classification,
                rationale, evidence_hash, ruleset_version, maturity, metadata_safe
            ) VALUES (
                :id, :tenant_id, :workspace_id, :trigger_id, :external_key, 'candidate', :service_key, :service_id,
                :asset_key, :asset_id,
                'Validate SIMATIC IoT2050 Advanced version and Node-RED configuration',
                'inventory_config_verify_iot2050', '1', 'needs_configuration_validation',
                :rationale, :hash, 'multisource-v1', 'fixture_tested', CAST(:meta AS jsonb)
            )
            ON CONFLICT (workspace_id, external_key) DO UPDATE SET rationale = EXCLUDED.rationale
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "tenant_id": snap["tenant_id"],
            "workspace_id": snap["workspace_id"],
            "trigger_id": trigger_id,
            "external_key": REC_KEY,
            "service_key": SERVICE_KEY,
            "service_id": service_id,
            "asset_key": ASSET_KEY,
            "asset_id": asset_id,
            "rationale": (
                "Synthetic Warehouse automation has a product identifier match for SIMATIC IoT2050 Advanced. "
                "Industrial OS version, Node-RED installation, authentication, and reachability remain unknown. "
                "Manual verification is required. This is not proof of exposure, attack, or customer impact."
            ),
            "hash": "warehouse-ot-verify-iot2050",
            "meta": json.dumps({"cve": CVE, "approval_required": True, "synthetic": True}),
        },
    )


def uninstall(connection) -> None:
    connection.execute(text("DELETE FROM readiness_recommendations WHERE external_key = :k"), {"k": REC_KEY})
    connection.execute(text("DELETE FROM readiness_triggers WHERE external_key = :k"), {"k": TRIGGER_KEY})
    connection.execute(text("DELETE FROM graph_edges WHERE source_key = :k"), {"k": EDGE_KEY})
    connection.execute(
        text(
            """
            DELETE FROM graph_service_memberships
             WHERE service_node_id IN (SELECT id FROM graph_nodes WHERE source_key = :s)
                OR member_node_id IN (SELECT id FROM graph_nodes WHERE source_key = :a)
            """
        ),
        {"s": SERVICE_KEY, "a": ASSET_KEY},
    )
    connection.execute(
        text("DELETE FROM graph_nodes WHERE source_key = :s OR source_key = :a"),
        {"s": SERVICE_KEY, "a": ASSET_KEY},
    )
    connection.execute(text("DELETE FROM intelligence_source_documents WHERE external_id = 'SSA-834709-fixture'"))
