"""Phase 1 Radar semantics, clustering, and workspace workflows.

Revision ID: 0011_phase1
Revises: 0010_phase0
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_phase1"
down_revision: str | None = "0010_phase0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.add_column("threat_sources", sa.Column("source_format", sa.String(32), nullable=False, server_default="json"))
    op.add_column("threat_sources", sa.Column("sync_mode", sa.String(32), nullable=False, server_default="automatic"))
    op.add_column("threat_sources", sa.Column("polling_minutes", sa.Integer(), nullable=False, server_default="60"))
    op.add_column("threat_sources", sa.Column("jurisdiction", sa.String(32)))
    op.add_column("threat_sources", sa.Column("license_url", sa.String(500)))
    op.add_column("threat_sources", sa.Column("storage_policy", sa.String(32), nullable=False, server_default="metadata_excerpt"))
    op.add_column("threat_sources", sa.Column("attribution", sa.String(500), nullable=False, server_default="Source attribution required"))
    op.add_column("threat_sources", sa.Column("parser_version", sa.String(64), nullable=False, server_default="phase0-v1"))
    op.add_column("threat_sources", sa.Column("last_success_at", sa.DateTime(timezone=True)))
    op.add_column("threat_sources", sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"))

    for name in (
        "authority_jurisdictions",
        "target_countries",
        "victim_countries",
        "infrastructure_countries",
        "prevalence_countries",
        "limitations",
    ):
        op.add_column(
            "threat_events",
            sa.Column(name, postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        )
    op.add_column("threat_events", sa.Column("exploitation_status", sa.String(32), nullable=False, server_default="unknown"))
    op.add_column("threat_events", sa.Column("source_payload_hash", sa.String(64), nullable=False, server_default=""))
    op.add_column("threat_events", sa.Column("parser_version", sa.String(64), nullable=False, server_default="phase0-v1"))
    op.add_column(
        "threat_events",
        sa.Column("provenance", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.execute(
        """
        UPDATE threat_events e
        SET authority_jurisdictions =
              CASE WHEN s.country IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(s.country) END,
            source_payload_hash = e.content_hash,
            event_type = CASE
              WHEN e.event_type = 'known_exploited_vulnerability' THEN 'vulnerability'
              WHEN e.event_type = 'national_advisory' THEN 'advisory'
              ELSE e.event_type
            END,
            exploitation_status = CASE
              WHEN e.event_type = 'known_exploited_vulnerability' THEN 'known_exploited'
              ELSE 'unknown'
            END,
            provenance = jsonb_build_object(
              'migration', '0011_phase1',
              'legacy_countries_semantics', 'reporting_authority_jurisdiction'
            ),
            limitations = jsonb_build_array(
              'Legacy Phase 0 country values were authority jurisdiction, not target or victim geography.'
            )
        FROM threat_sources s
        WHERE s.id = e.source_id
        """
    )

    op.create_table(
        "threat_clusters",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(128), nullable=False, unique=True),
        sa.Column("relationship_type", sa.String(32), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("factors", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("algorithm_version", sa.String(64), nullable=False),
        *timestamps(),
    )
    op.create_table(
        "threat_cluster_memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threat_clusters.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("threat_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship_type", sa.String(32), nullable=False),
        sa.Column("factors", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        *timestamps(),
        sa.UniqueConstraint("cluster_id", "event_id", name="uq_threat_cluster_membership"),
    )
    op.create_index("ix_threat_cluster_memberships_event", "threat_cluster_memberships", ["event_id"])

    op.create_table(
        "radar_saved_views",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("filters", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("updated_by", sa.String(200), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("workspace_id", "name", name="uq_radar_saved_view_workspace_name"),
    )
    op.create_index("ix_radar_saved_views_workspace", "radar_saved_views", ["workspace_id"])
    op.create_table(
        "radar_triage",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject_type", sa.String(16), nullable=False),
        sa.Column("subject_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("priority", sa.String(32), nullable=False),
        sa.Column("owner", sa.String(200)),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("workspace_id", "subject_type", "subject_id", name="uq_radar_triage_subject"),
        sa.CheckConstraint("subject_type IN ('event', 'cluster')", name="ck_radar_triage_subject_type"),
    )
    op.create_index("ix_radar_triage_workspace_status", "radar_triage", ["workspace_id", "status"])
    op.create_table(
        "business_services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("criticality", sa.String(32), nullable=False, server_default="unknown"),
        *timestamps(),
        sa.UniqueConstraint("workspace_id", "key", name="uq_business_service_workspace_key"),
    )
    op.create_index("ix_business_services_workspace", "business_services", ["workspace_id"])
    op.create_table(
        "workspace_resource_bindings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("resource_type", sa.String(32), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("label", sa.String(300), nullable=False),
        sa.Column("bound_by", sa.String(200), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("workspace_id", "resource_type", "resource_id", name="uq_workspace_resource_binding"),
        sa.CheckConstraint("resource_type IN ('control', 'evidence', 'system')", name="ck_workspace_resource_binding_type"),
    )
    op.create_index("ix_workspace_resource_bindings_workspace", "workspace_resource_bindings", ["workspace_id", "resource_type"])
    op.create_table(
        "radar_readiness_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject_type", sa.String(16), nullable=False),
        sa.Column("subject_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("provenance", sa.String(500), nullable=False),
        sa.Column("limitations", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("actor", sa.String(200), nullable=False),
        *timestamps(),
        sa.UniqueConstraint(
            "workspace_id", "subject_type", "subject_id", "target_type", "target_id",
            name="uq_radar_readiness_link",
        ),
        sa.CheckConstraint("subject_type IN ('event', 'cluster')", name="ck_radar_link_subject_type"),
        sa.CheckConstraint(
            "target_type IN ('control', 'evidence', 'system', 'business_service')",
            name="ck_radar_link_target_type",
        ),
    )
    op.create_index(
        "ix_radar_readiness_links_subject",
        "radar_readiness_links",
        ["workspace_id", "subject_type", "subject_id"],
    )
    op.create_table(
        "radar_workflow_audit",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_radar_workflow_audit_workspace_at", "radar_workflow_audit", ["workspace_id", "at"])

    op.execute(
        """
        UPDATE threat_sources SET
          source_format = CASE key WHEN 'cisa-kev' THEN 'json' WHEN 'first-epss' THEN 'json' ELSE 'rss' END,
          jurisdiction = country,
          storage_policy = CASE key WHEN 'cisa-kev' THEN 'structured_full' WHEN 'first-epss' THEN 'numeric_only' ELSE 'metadata_excerpt' END,
          attribution = CASE key
            WHEN 'cisa-kev' THEN 'CISA Known Exploited Vulnerabilities (CC0 1.0)'
            WHEN 'first-epss' THEN 'FIRST Exploit Prediction Scoring System'
            ELSE 'Norwegian National Security Authority (NSM)'
          END,
          parser_version = 'phase1-v1',
          license_url = CASE key
            WHEN 'cisa-kev' THEN 'https://www.cisa.gov/sites/default/files/licenses/kev/license.txt'
            WHEN 'first-epss' THEN 'https://www.first.org/about/policies/terms'
            ELSE NULL
          END
        """
    )
    op.execute(
        """
        INSERT INTO threat_sources
          (id, key, provider, authority, country, jurisdiction, locator, source_format, sync_mode,
           polling_minutes, license_url, storage_policy, attribution, parser_version, enabled)
        VALUES
          ('00000000-0000-4000-8000-000000000023', 'cert-se-atom', 'CERT-SE',
           'Swedish National Cybersecurity Centre / FRA', 'SE', 'SE',
           'https://www.cert.se/feed/atom.xml', 'atom', 'automatic', 60, NULL,
           'metadata_excerpt', 'CERT-SE / Swedish National Cybersecurity Centre', 'phase1-v1', true),
          ('00000000-0000-4000-8000-000000000024', 'ncsc-fi-rss', 'NCSC-FI',
           'National Cyber Security Centre Finland / Traficom', 'FI', 'FI',
           'https://www.kyberturvallisuuskeskus.fi/feed/rss/fi/400', 'rss', 'automatic', 60, NULL,
           'metadata_excerpt', 'NCSC-FI / Finnish Transport and Communications Agency Traficom', 'phase1-v1', true),
          ('00000000-0000-4000-8000-000000000025', 'enisa-euvd', 'ENISA EUVD',
           'European Union Agency for Cybersecurity', NULL, 'EU',
           'https://euvdservices.enisa.europa.eu/api/search', 'json', 'automatic', 60,
           'https://www.enisa.europa.eu/about-enisa/legal-notice',
           'metadata_excerpt', 'European Union Agency for Cybersecurity (ENISA)', 'phase1-v1', true),
          ('00000000-0000-4000-8000-000000000026', 'cert-eu-rss', 'CERT-EU',
           'Computer Emergency Response Team for EU institutions', NULL, 'EU',
           'https://cert.europa.eu/publications/security-advisories-rss', 'rss', 'automatic', 60,
           'https://cert.europa.eu/legal-notice',
           'metadata_excerpt', 'CERT-EU (CC BY 4.0 unless otherwise noted)', 'phase1-v1', true),
          ('00000000-0000-4000-8000-000000000027', 'samsik-manual', 'SAMSIK',
           'Danish Agency for Societal Security and Emergency Management', 'DK', 'DK',
           'https://www.sikkerdigital.dk/', 'manual_metadata', 'manual', 1440, NULL,
           'metadata_link_only', 'SAMSIK / Sikkerdigital', 'manual-metadata-v1', true),
          ('00000000-0000-4000-8000-000000000028', 'cert-is-manual', 'CERT-IS',
           'Icelandic national CERT', 'IS', 'IS',
           'https://cert.is/', 'manual_metadata', 'manual', 1440, NULL,
           'metadata_link_only', 'CERT-IS', 'manual-metadata-v1', true)
        ON CONFLICT (key) DO NOTHING
        """
    )
    op.execute(
        """
        INSERT INTO business_services (id, workspace_id, key, name, description, criticality)
        VALUES (
          '00000000-0000-4000-8000-000000000030',
          '00000000-0000-4000-8000-000000000010',
          'customer-operations',
          'Customer operations',
          'Phase 0 organization-profile critical service.',
          'high'
        )
        ON CONFLICT (workspace_id, key) DO NOTHING
        """
    )
    op.execute(
        """
        INSERT INTO workspace_resource_bindings (id, workspace_id, resource_type, resource_id, label, bound_by)
        SELECT md5('control:' || id::text)::uuid, '00000000-0000-4000-8000-000000000010',
               'control', id, identifier || ' — ' || title, 'phase1-migration'
        FROM controls
        ON CONFLICT (workspace_id, resource_type, resource_id) DO NOTHING
        """
    )
    op.execute(
        """
        INSERT INTO workspace_resource_bindings (id, workspace_id, resource_type, resource_id, label, bound_by)
        SELECT md5('evidence:' || id::text)::uuid, '00000000-0000-4000-8000-000000000010',
               'evidence', id, title, 'phase1-migration'
        FROM evidence_records
        ON CONFLICT (workspace_id, resource_type, resource_id) DO NOTHING
        """
    )
    op.execute(
        """
        INSERT INTO workspace_resource_bindings (id, workspace_id, resource_type, resource_id, label, bound_by)
        SELECT md5('system:' || id::text)::uuid, '00000000-0000-4000-8000-000000000010',
               'system', id, name || ' (' || environment || ')', 'phase1-migration'
        FROM ai_systems
        ON CONFLICT (workspace_id, resource_type, resource_id) DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_index("ix_radar_workflow_audit_workspace_at", table_name="radar_workflow_audit")
    op.drop_table("radar_workflow_audit")
    op.drop_index("ix_radar_readiness_links_subject", table_name="radar_readiness_links")
    op.drop_table("radar_readiness_links")
    op.drop_index("ix_workspace_resource_bindings_workspace", table_name="workspace_resource_bindings")
    op.drop_table("workspace_resource_bindings")
    op.drop_index("ix_business_services_workspace", table_name="business_services")
    op.drop_table("business_services")
    op.drop_index("ix_radar_triage_workspace_status", table_name="radar_triage")
    op.drop_table("radar_triage")
    op.drop_index("ix_radar_saved_views_workspace", table_name="radar_saved_views")
    op.drop_table("radar_saved_views")
    op.drop_index("ix_threat_cluster_memberships_event", table_name="threat_cluster_memberships")
    op.drop_table("threat_cluster_memberships")
    op.drop_table("threat_clusters")
    op.execute(
        """
        DELETE FROM threat_events
        WHERE source_id IN (
          SELECT id FROM threat_sources
          WHERE key IN ('cert-se-atom','ncsc-fi-rss','enisa-euvd','cert-eu-rss','samsik-manual','cert-is-manual')
        )
        """
    )
    op.execute("DELETE FROM threat_sources WHERE key IN ('cert-se-atom','ncsc-fi-rss','enisa-euvd','cert-eu-rss','samsik-manual','cert-is-manual')")
    for name in (
        "provenance", "parser_version", "source_payload_hash", "exploitation_status",
        "limitations", "prevalence_countries", "infrastructure_countries",
        "victim_countries", "target_countries", "authority_jurisdictions",
    ):
        op.drop_column("threat_events", name)
    for name in (
        "consecutive_failures", "last_success_at", "parser_version", "attribution",
        "storage_policy", "license_url", "jurisdiction", "polling_minutes", "sync_mode",
        "source_format",
    ):
        op.drop_column("threat_sources", name)
