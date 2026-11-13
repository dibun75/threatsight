"""M7 threat intelligence tables and curated catalog seed.

Revision ID: 0007_m7
Revises: 0006_m6
Create Date: 2026-08-27
"""

from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from threatsight_api.threats.catalog import ADVISORIES, CATALOG_VERSION, TECHNIQUES, THREATS

revision: str = "0007_m7"
down_revision: str | None = "0006_m6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "intel_threats",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("catalog_version", sa.String(32), nullable=False),
        sa.Column("informational_only", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("key", name="uq_intel_threats_key"),
    )
    op.create_table(
        "intel_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column(
            "threat_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("intel_threats.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("locator", sa.String(500), nullable=False),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("catalog_version", sa.String(32), nullable=False),
        sa.Column("framework_key", sa.String(64)),
        sa.Column("reference_code", sa.String(64)),
        sa.Column("informational_only", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("key", name="uq_intel_techniques_key"),
    )
    op.create_index("ix_intel_techniques_threat", "intel_techniques", ["threat_id"])
    op.create_table(
        "intel_advisories",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("locator", sa.String(500), nullable=False),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("catalog_version", sa.String(32), nullable=False),
        sa.Column("ingested_by", sa.String(200), nullable=False),
        sa.Column("informational_only", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("key", name="uq_intel_advisories_key"),
    )
    op.create_table(
        "intel_advisory_techniques",
        sa.Column(
            "advisory_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("intel_advisories.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "technique_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("intel_techniques.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    op.create_table(
        "intel_technique_controls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "technique_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("intel_techniques.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "control_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("controls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("note", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("technique_id", "control_id", name="uq_intel_technique_control"),
    )
    op.create_index("ix_intel_technique_controls_control", "intel_technique_controls", ["control_id"])
    op.create_table(
        "intel_technique_tests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "technique_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("intel_techniques.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scenario_key", sa.String(32), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("technique_id", "scenario_key", name="uq_intel_technique_test"),
    )

    conn = op.get_bind()
    threat_ids: dict[str, str] = {}
    for item in THREATS:
        row = conn.execute(
            sa.text("SELECT id FROM intel_threats WHERE key = :key"),
            {"key": item.key},
        ).fetchone()
        if row is None:
            threat_id = str(uuid4())
            conn.execute(
                sa.text(
                    """
                    INSERT INTO intel_threats (id, key, title, statement, catalog_version, informational_only)
                    VALUES (:id, :key, :title, :statement, :version, true)
                    """
                ),
                {
                    "id": threat_id,
                    "key": item.key,
                    "title": item.title[:200],
                    "statement": item.statement,
                    "version": CATALOG_VERSION,
                },
            )
        else:
            threat_id = str(row[0])
            conn.execute(
                sa.text(
                    """
                    UPDATE intel_threats
                    SET title = :title, statement = :statement, catalog_version = :version, informational_only = true
                    WHERE id = :id
                    """
                ),
                {
                    "id": threat_id,
                    "title": item.title[:200],
                    "statement": item.statement,
                    "version": CATALOG_VERSION,
                },
            )
        threat_ids[item.key] = threat_id

    technique_ids: dict[str, str] = {}
    for item in TECHNIQUES:
        row = conn.execute(
            sa.text("SELECT id FROM intel_techniques WHERE key = :key"),
            {"key": item.key},
        ).fetchone()
        if row is None:
            technique_id = str(uuid4())
            conn.execute(
                sa.text(
                    """
                    INSERT INTO intel_techniques
                    (id, key, threat_id, title, statement, locator, source_kind, catalog_version,
                     framework_key, reference_code, informational_only)
                    VALUES
                    (:id, :key, :threat_id, :title, :statement, :locator, :source_kind, :version,
                     :framework_key, :reference_code, true)
                    """
                ),
                {
                    "id": technique_id,
                    "key": item.key,
                    "threat_id": threat_ids[item.threat_key],
                    "title": item.title[:200],
                    "statement": item.statement,
                    "locator": item.locator,
                    "source_kind": item.source_kind,
                    "version": CATALOG_VERSION,
                    "framework_key": item.framework_key,
                    "reference_code": item.reference_code,
                },
            )
        else:
            technique_id = str(row[0])
            conn.execute(
                sa.text(
                    """
                    UPDATE intel_techniques
                    SET threat_id = :threat_id, title = :title, statement = :statement, locator = :locator,
                        source_kind = :source_kind, catalog_version = :version, framework_key = :framework_key,
                        reference_code = :reference_code, informational_only = true
                    WHERE id = :id
                    """
                ),
                {
                    "id": technique_id,
                    "threat_id": threat_ids[item.threat_key],
                    "title": item.title[:200],
                    "statement": item.statement,
                    "locator": item.locator,
                    "source_kind": item.source_kind,
                    "version": CATALOG_VERSION,
                    "framework_key": item.framework_key,
                    "reference_code": item.reference_code,
                },
            )
        technique_ids[item.key] = technique_id

    for item in ADVISORIES:
        row = conn.execute(
            sa.text("SELECT id FROM intel_advisories WHERE key = :key"),
            {"key": item.key},
        ).fetchone()
        if row is None:
            advisory_id = str(uuid4())
            conn.execute(
                sa.text(
                    """
                    INSERT INTO intel_advisories
                    (id, key, title, summary, locator, source_kind, catalog_version, ingested_by, informational_only)
                    VALUES
                    (:id, :key, :title, :summary, :locator, :source_kind, :version, :actor, true)
                    """
                ),
                {
                    "id": advisory_id,
                    "key": item.key,
                    "title": item.title[:200],
                    "summary": item.summary,
                    "locator": item.locator,
                    "source_kind": item.source_kind,
                    "version": CATALOG_VERSION,
                    "actor": "migration",
                },
            )
        else:
            advisory_id = str(row[0])
            conn.execute(
                sa.text(
                    """
                    UPDATE intel_advisories
                    SET title = :title, summary = :summary, locator = :locator, source_kind = :source_kind,
                        catalog_version = :version, informational_only = true
                    WHERE id = :id
                    """
                ),
                {
                    "id": advisory_id,
                    "title": item.title[:200],
                    "summary": item.summary,
                    "locator": item.locator,
                    "source_kind": item.source_kind,
                    "version": CATALOG_VERSION,
                },
            )
        for technique_key in item.technique_keys:
            conn.execute(
                sa.text(
                    """
                    INSERT INTO intel_advisory_techniques (advisory_id, technique_id)
                    VALUES (:advisory_id, :technique_id)
                    ON CONFLICT DO NOTHING
                    """
                ),
                {"advisory_id": advisory_id, "technique_id": technique_ids[technique_key]},
            )


def downgrade() -> None:
    op.drop_table("intel_technique_tests")
    op.drop_index("ix_intel_technique_controls_control", table_name="intel_technique_controls")
    op.drop_table("intel_technique_controls")
    op.drop_table("intel_advisory_techniques")
    op.drop_table("intel_advisories")
    op.drop_index("ix_intel_techniques_threat", table_name="intel_techniques")
    op.drop_table("intel_techniques")
    op.drop_table("intel_threats")
