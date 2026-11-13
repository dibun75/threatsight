"""Authoritative product-intelligence landscape.

Revision ID: 0018_threat_landscape
Revises: 0017_public_demo
"""

from __future__ import annotations

import hashlib
import json
import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

from threatsight_api.landscape.sanitize import cve_list, plain, safe_https
from threatsight_api.landscape.seed import ADVISORIES, SOURCES

revision = "0018_threat_landscape"
down_revision = "0017_public_demo"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("threat_sources", sa.Column("auth_requirement", sa.String(32), nullable=False, server_default="none"))
    op.add_column("threat_sources", sa.Column("maturity", sa.String(32), nullable=False, server_default="unspecified"))
    op.add_column("threat_sources", sa.Column("terms_note", sa.String(500), nullable=False, server_default=""))
    op.add_column("threat_sources", sa.Column("rate_limit_note", sa.String(200), nullable=False, server_default=""))
    op.add_column("threat_sources", sa.Column("limitations", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.execute(
        """
        UPDATE threat_sources
           SET maturity = 'live_verified',
               terms_note = 'Collected by the existing Phase 1 adapter before this landscape phase.'
         WHERE last_status = 'ok'
        """
    )
    op.execute(
        """
        UPDATE threat_sources
           SET maturity = 'unsupported',
               sync_mode = 'manual',
               terms_note = 'No verified machine contract is enabled.'
         WHERE key IN ('cert-is-manual', 'samsik-manual')
        """
    )
    op.execute(
        """
        UPDATE threat_sources
           SET maturity = 'fixture_tested',
               terms_note = 'Synthetic correlation fixture. Not a public intelligence feed.'
         WHERE key = 'synthetic-correlation'
        """
    )
    op.create_table(
        "landscape_advisories",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_key", sa.String(64), nullable=False),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("canonical_url", sa.String(1000), nullable=False),
        sa.Column("vendor", sa.String(200), nullable=False),
        sa.Column("vendor_advisory_id", sa.String(200), nullable=False),
        sa.Column("cves", JSONB, nullable=False),
        sa.Column("vendor_severity", sa.String(32), nullable=False),
        sa.Column("cvss_score", sa.Float()),
        sa.Column("cvss_vector", sa.String(200)),
        sa.Column("cvss_version", sa.String(16)),
        sa.Column("vex_status", sa.String(32), nullable=False),
        sa.Column("kev_listed", sa.Boolean(), nullable=False),
        sa.Column("epss_score", sa.Float()),
        sa.Column("epss_percentile", sa.Float()),
        sa.Column("exploitation_claim", sa.String(32), nullable=False),
        sa.Column("withdrawn", sa.Boolean(), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("conflict", sa.Boolean(), nullable=False),
        sa.Column("maturity", sa.String(32), nullable=False),
        sa.Column("parser_version", sa.String(64), nullable=False),
        sa.Column("evidence_hash", sa.String(64), nullable=False),
        sa.Column("products", JSONB, nullable=False),
        sa.Column("geography", JSONB, nullable=False),
        sa.Column("limitations", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("source_key", "external_id", name="uq_landscape_advisory_source"),
    )
    op.create_table(
        "landscape_catalog",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("vendor", sa.String(200), nullable=False),
        sa.Column("family", sa.String(200), nullable=False),
        sa.Column("product", sa.String(200), nullable=False),
        sa.Column("version_scheme", sa.String(32), nullable=False),
        sa.Column("aliases", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.UniqueConstraint("vendor", "product", name="uq_landscape_catalog_product"),
    )
    bind = op.get_bind()
    for source in SOURCES:
        bind.execute(
            sa.text(
                """
                INSERT INTO threat_sources (
                    id, key, provider, authority, country, locator, source_format, sync_mode,
                    polling_minutes, jurisdiction, license_url, storage_policy, attribution,
                    parser_version, enabled, last_status, auth_requirement, maturity, terms_note,
                    rate_limit_note, limitations
                ) VALUES (
                    :id, :key, :provider, :authority, :country, :locator, :source_format, 'manual',
                    1440, :country, :locator, 'metadata_excerpt', :authority,
                    'landscape-v1', false, 'never', :auth_requirement, :maturity, :terms_note,
                    'Not called during normal startup or a web request.', '[]'::jsonb
                )
                ON CONFLICT (key) DO NOTHING
                """
            ),
            {**source, "id": str(uuid.uuid4())},
        )
    catalog = {}
    for item in ADVISORIES:
        title = plain(item["title"], 500)
        summary = plain(item["summary"], 2000)
        url = safe_https(item["url"]) or "https://threatsight.io/landscape"
        cves = cve_list(item["cves"])
        products = []
        for product in item["products"][:8]:
            products.append(
                {
                    "vendor": plain(product["vendor"], 80),
                    "family": plain(product["family"], 80),
                    "product": plain(product["product"], 80),
                    "scheme": plain(product["scheme"], 32),
                    "constraint": plain(product.get("constraint") or "", 80),
                    "fixed": plain(product.get("fixed") or "", 80),
                    "observed": plain(product.get("observed") or "", 80),
                }
            )
            catalog[(products[-1]["vendor"], products[-1]["product"])] = (
                products[-1]["family"],
                products[-1]["scheme"],
            )
        geography = []
        for geo in item["geo"][:8]:
            country = plain(geo["country"], 2).upper()
            if len(country) == 2 and country.isalpha():
                geography.append(
                    {
                        "role": plain(geo["role"], 40),
                        "country": country,
                        "note": plain(geo["note"], 200),
                    }
                )
        digest = hashlib.sha256(json.dumps({"title": title, "cves": cves, "url": url}, sort_keys=True).encode()).hexdigest()
        source_maturity = next(row["maturity"] for row in SOURCES if row["key"] == item["source"]) if item["source"] in {row["key"] for row in SOURCES} else "fixture_tested"
        if item["source"] in {"cisa-kev", "first-epss", "cert-se-atom", "ncsc-fi-rss"}:
            source_maturity = "fixture_tested"
        bind.execute(
            sa.text(
                """
                INSERT INTO landscape_advisories (
                    id, source_key, external_id, title, summary, canonical_url, vendor,
                    vendor_advisory_id, cves, vendor_severity, cvss_score, cvss_vector, cvss_version,
                    vex_status, kev_listed, epss_score, epss_percentile, exploitation_claim, withdrawn,
                    freshness, conflict, maturity, parser_version, evidence_hash, products, geography, limitations
                ) VALUES (
                    :id, :source_key, :external_id, :title, :summary, :canonical_url, :vendor,
                    :vendor_advisory_id, CAST(:cves AS jsonb), :vendor_severity, :cvss_score, :cvss_vector, :cvss_version,
                    :vex_status, :kev_listed, :epss_score, :epss_percentile, :exploitation_claim, :withdrawn,
                    :freshness, :conflict, :maturity, 'landscape-v1', :evidence_hash, CAST(:products AS jsonb), CAST(:geography AS jsonb),
                    CAST(:limitations AS jsonb)
                )
                """
            ),
            {
                "id": item["id"],
                "source_key": item["source"],
                "external_id": item["external_id"],
                "title": title,
                "summary": summary,
                "canonical_url": url,
                "vendor": plain(item["vendor"], 80),
                "vendor_advisory_id": plain(item["vendor_id"], 80),
                "cves": json.dumps(cves),
                "vendor_severity": plain(item["vendor_severity"], 32),
                "cvss_score": item["cvss_score"],
                "cvss_vector": plain(item["cvss_vector"], 120),
                "cvss_version": plain(item["cvss_version"], 16),
                "vex_status": plain(item["vex"], 32),
                "kev_listed": bool(item["kev"]),
                "epss_score": item["epss"],
                "epss_percentile": item["epss_percentile"],
                "exploitation_claim": plain(item["exploitation"], 32),
                "withdrawn": bool(item["withdrawn"]),
                "freshness": plain(item["freshness"], 32),
                "conflict": bool(item["conflict"]),
                "maturity": source_maturity,
                "evidence_hash": digest,
                "products": json.dumps(products),
                "geography": json.dumps(geography),
                "limitations": json.dumps(
                    [
                        "fixture_tested" if source_maturity != "live_verified" else "collected",
                        "not_customer_inventory",
                        "not_attacker_origin",
                    ]
                ),
            },
        )
    for (vendor, product), (family, scheme) in sorted(catalog.items()):
        bind.execute(
            sa.text(
                """
                INSERT INTO landscape_catalog (id, vendor, family, product, version_scheme, aliases)
                VALUES (:id, :vendor, :family, :product, :scheme, '[]'::jsonb)
                ON CONFLICT (vendor, product) DO NOTHING
                """
            ),
            {"id": str(uuid.uuid4()), "vendor": vendor, "family": family, "product": product, "scheme": scheme},
        )


def downgrade() -> None:
    op.drop_table("landscape_catalog")
    op.drop_table("landscape_advisories")
    op.execute(
        """
        DELETE FROM threat_sources
         WHERE key IN (
            'msrc-csaf', 'cisco-openvuln', 'fortinet-psirt', 'paloalto-advisory',
            'aws-bulletins', 'google-cloud-bulletins', 'nvd-cve', 'juniper-psirt'
         )
        """
    )
    op.drop_column("threat_sources", "limitations")
    op.drop_column("threat_sources", "rate_limit_note")
    op.drop_column("threat_sources", "terms_note")
    op.drop_column("threat_sources", "maturity")
    op.drop_column("threat_sources", "auth_requirement")
