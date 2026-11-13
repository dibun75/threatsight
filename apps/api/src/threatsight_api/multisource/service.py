"""Read APIs for emerging exploitation clusters and source health."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.multisource.reference import ASSET_KEY, MODEL, SERVICE_KEY
from threatsight_api.persistence.graph_models import GraphNode
from threatsight_api.persistence.multisource_models import (
    IntelligenceAssertion,
    IntelligenceChangeEvent,
    IntelligenceCluster,
    IntelligenceClusterDocument,
    IntelligenceSourceDocument,
    IntelligenceSourceHealth,
)
from threatsight_api.persistence.models import VulnerabilitySignal
from threatsight_api.persistence.landscape_models import LandscapeAdvisory


def list_clusters(db: Session, *, limit: int = 50) -> dict[str, Any]:
    rows = list(
        db.scalars(select(IntelligenceCluster).order_by(IntelligenceCluster.updated_at.desc()).limit(min(limit, 100)))
    )
    return {"items": [_cluster_summary(db, row) for row in rows]}


def cluster_detail(db: Session, cluster_id: uuid.UUID) -> dict[str, Any]:
    cluster = db.get(IntelligenceCluster, cluster_id)
    if cluster is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Not found")
    doc_ids = list(
        db.scalars(
            select(IntelligenceClusterDocument.document_id).where(IntelligenceClusterDocument.cluster_id == cluster.id)
        )
    )
    documents = list(db.scalars(select(IntelligenceSourceDocument).where(IntelligenceSourceDocument.id.in_(doc_ids)))) if doc_ids else []
    assertions = list(db.scalars(select(IntelligenceAssertion).where(IntelligenceAssertion.document_id.in_(doc_ids)))) if doc_ids else []
    changes = list(
        db.scalars(
            select(IntelligenceChangeEvent)
            .where(IntelligenceChangeEvent.cluster_id == cluster.id)
            .order_by(IntelligenceChangeEvent.detected_at.desc())
            .limit(50)
        )
    )
    cve = cluster.primary_key_value
    # CISA KEV remains a separate dated landscape fact (JSONB cves list), not derived from media.
    kev = bool(
        db.scalar(
            select(LandscapeAdvisory.id)
            .where(LandscapeAdvisory.kev_listed.is_(True), LandscapeAdvisory.cves.contains([cve]))
            .limit(1)
        )
    )
    epss = db.scalar(select(VulnerabilitySignal).where(VulnerabilitySignal.cve == cve))
    org = _organization_relevance(db, cve)
    return {
        **_cluster_summary(db, cluster),
        "what_changed": [ {"type": c.change_type, "reason": c.materiality_reason, "at": c.detected_at.isoformat(), "source": c.source_key} for c in changes],
        "vendor_facts": [_assertion_out(a) for a in assertions if a.source_role == "vendor_authority"],
        "exploitation_observations": [
            _assertion_out(a)
            for a in assertions
            if a.source_role == "exploitation_observation"
            and a.assertion_type in {"researcher_exploitation_observed", "exploitation_directly_observed"}
        ],
        "exploitation_catalog": [
            _assertion_out(a)
            for a in assertions
            if a.source_role == "exploitation_observation" and a.assertion_type == "researcher_catalogued"
        ],
        "media_coverage": [_document_out(d) for d in documents if d.source_role == "media_discovery"],
        "government_status": {
            "label": "CISA KEV",
            "cisa_kev_listed": kev,
            "as_of": None,
            "note": "Separate government fact. Absence is not proof of no exploitation.",
        },
        "probability_estimate": {
            "label": "FIRST EPSS",
            "epss_score": None if epss is None else epss.epss_score,
            "epss_date": None if epss is None or epss.score_date is None else epss.score_date.date().isoformat(),
            "note": "Dated probability estimate. Not confirmation of exploitation.",
        },
        "documents": [_document_out(d) for d in documents],
        "assertions": [_assertion_out(a) for a in assertions],
        "organization_matches": org,
        "known_versus_unknown": org.get("known_versus_unknown", []),
        "recommended_verification": org.get("recommended_verification"),
        "labels": {
            "vendor_advisory": "Siemens ProductCERT — Vendor advisory",
            "researcher": "VulnCheck canary — Exploitation observed by researcher",
            "catalog": "VulnCheck KEV — Exploitation catalog",
            "media": "The Hacker News — Media report",
            "government": "CISA KEV",
            "probability": "FIRST EPSS",
        },
        "headline": _exploitation_headline(cluster.exploitation_state),
        "does_not_mean": [
            "This cluster is not proof the organization was attacked.",
            "Media reports are not vendor truth.",
            "A vendor vulnerability advisory is not vendor confirmation of active exploitation.",
            "Researcher observations elsewhere are not customer targeting.",
        ],
    }


def source_health(db: Session) -> dict[str, Any]:
    rows = list(db.scalars(select(IntelligenceSourceHealth).order_by(IntelligenceSourceHealth.source_key)))
    items = []
    for row in rows:
        health = "disabled"
        err = row.last_error_code or ""
        if row.kill_switch:
            health = "kill_switch"
        elif row.token_required and (not row.enabled or err in {"token_missing"}):
            health = "credential_required"
        elif not row.enabled:
            health = "disabled"
        elif err == "unauthorized":
            health = "unauthorized"
        elif err == "rate_limited":
            health = "rate_limited"
        elif err == "schema_drift":
            health = "schema_drift"
        elif err and row.consecutive_failures >= 1 and row.last_known_good_hash:
            health = "failed_with_last_known_good"
        elif err and row.consecutive_failures >= 3:
            health = "failed"
        elif row.enabled and row.last_success_at is None and not err:
            health = "connected"
        elif row.last_success_at is None:
            health = "never_succeeded"
        else:
            health = "current"
        items.append(
            {
                "source_key": row.source_key,
                "source_role": row.source_role,
                "enabled": row.enabled,
                "kill_switch": row.kill_switch,
                "maturity": row.maturity,
                "token_required": row.token_required,
                "token_configured": False if row.token_required else None,
                "health": health,
                "last_success_at": None if row.last_success_at is None else row.last_success_at.isoformat(),
                "last_attempt_at": None if row.last_attempt_at is None else row.last_attempt_at.isoformat(),
                "last_error_code": row.last_error_code,
                "role_label": {
                    "vendor_authority": "Vendor advisory",
                    "government_authority": "CISA KEV",
                    "exploitation_observation": "Exploitation observation",
                    "media_discovery": "Media report",
                }.get(row.source_role, row.source_role),
            }
        )
    return {"items": items}


def _exploitation_headline(state: str) -> str:
    return {
        "researcher_observed": "Exploitation observed by a security researcher",
        "vendor_confirmed": "Vendor confirmed known active exploitation",
        "government_catalogued": "Government catalog lists exploitation",
        "media_reported": "Media reported exploitation",
        "not_reported": "Exploitation not reported in collected evidence",
        "conflicting": "Conflicting exploitation evidence",
        "withdrawn": "Exploitation claim withdrawn",
        "unknown": "Exploitation evidence incomplete",
    }.get(state, "Exploitation evidence incomplete")


def _cluster_summary(db: Session, cluster: IntelligenceCluster) -> dict[str, Any]:
    return {
        "id": str(cluster.id),
        "cve": cluster.primary_key_value if cluster.primary_key_type == "cve" else None,
        "primary_key_type": cluster.primary_key_type,
        "primary_key_value": cluster.primary_key_value,
        "title": cluster.title,
        "exploitation_state": cluster.exploitation_state,
        "exploitation_explanation": cluster.exploitation_explanation,
        "headline": _exploitation_headline(cluster.exploitation_state),
        "aliases": cluster.aliases,
        "maturity": cluster.maturity,
        "updated_at": cluster.updated_at.isoformat(),
        "organization_relevance": _organization_relevance(db, cluster.primary_key_value).get("summary"),
    }


def _document_out(doc: IntelligenceSourceDocument) -> dict[str, Any]:
    return {
        "id": str(doc.id),
        "source_key": doc.source_key,
        "source_role": doc.source_role,
        "external_id": doc.external_id,
        "title": doc.title,
        "canonical_url": doc.canonical_url,
        "published_at": None if doc.published_at is None else doc.published_at.isoformat(),
        "metadata_safe": doc.metadata_safe,
        "correction_state": doc.correction_state,
        "maturity": doc.maturity,
    }


def _assertion_out(row: IntelligenceAssertion) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "subject_key": row.subject_key,
        "assertion_type": row.assertion_type,
        "value": row.value,
        "source_role": row.source_role,
        "observed_at": None if row.observed_at is None else row.observed_at.isoformat(),
        "limitations": row.limitations,
        "provenance": row.provenance,
    }


def _organization_relevance(db: Session, cve: str) -> dict[str, Any]:
    asset = db.scalar(
        select(GraphNode).where(GraphNode.source_key == ASSET_KEY, GraphNode.lifecycle == "active").limit(1)
    )
    service = db.scalar(
        select(GraphNode).where(GraphNode.source_key == SERVICE_KEY, GraphNode.lifecycle == "active").limit(1)
    )
    if asset is None:
        return {
            "summary": "No stored organization technology identifier currently matches this cluster.",
            "match_classification": "unknown",
            "services": [],
            "known_versus_unknown": [],
            "recommended_verification": None,
        }
    attrs = asset.attributes or {}
    model_ok = MODEL in str(attrs.get("model_number") or "") or MODEL in str(asset.vendor_id or "")
    # Strong-identifier chain only: CVE must be the reviewed synthetic journey CVE and the
    # exact model/order identifier must be present. Owning another Siemens product is not a match.
    from threatsight_api.multisource.reference import CVE as WAREHOUSE_CVE

    if cve != WAREHOUSE_CVE or not model_ok:
        return {
            "summary": "No strong-identifier match for this CVE in the synthetic inventory.",
            "match_classification": "not_applicable_by_evidence",
            "services": [],
            "known_versus_unknown": [],
            "recommended_verification": None,
        }
    known = [
        f"Product identifier match: SIMATIC IoT2050 Advanced / {MODEL} (synthetic).",
        f"Business service dependency: {service.label if service else 'Warehouse automation'} (configured, not observed).",
    ]
    unknown = [
        "Industrial OS version: unknown",
        "Node-RED installed: unknown",
        "Node-RED authentication: unknown",
        "Internet reachability: unknown",
    ]
    return {
        "summary": "Synthetic product identifier match with configuration unknowns. Not confirmed exposure.",
        "match_classification": "needs_configuration_validation",
        "services": [{"id": str(service.id), "label": service.label, "synthetic": True}] if service else [],
        "assets": [{"id": str(asset.id), "label": asset.label, "synthetic": True}],
        "known_versus_unknown": {"known": known, "unknown": unknown},
        "recommended_verification": {
            "title": "Validate version, Node-RED installation, authentication, and reachability",
            "approval_required": True,
            "note": "Manual verification only. No automatic execution.",
        },
    }
