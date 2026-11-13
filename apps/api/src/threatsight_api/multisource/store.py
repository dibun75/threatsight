"""Persist documents, assertions, clusters and derive exploitation state."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.multisource import EXPLOITATION_ASSERTION_TYPES, RULESET_VERSION
from threatsight_api.persistence.multisource_models import (
    IntelligenceAssertion,
    IntelligenceChangeEvent,
    IntelligenceCluster,
    IntelligenceClusterDocument,
    IntelligenceSourceDocument,
)


def content_hash(document: dict[str, Any]) -> str:
    blob = json.dumps(
        {
            "title": document.get("title"),
            "external_id": document.get("external_id"),
            "metadata_safe": document.get("metadata_safe"),
            "assertions": document.get("assertions"),
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(blob.encode()).hexdigest()


def _normalize_exploitation_types(assertion_types: set[str]) -> set[str]:
    """Map legacy assertion names and drop non-exploitation vendor facts."""
    out: set[str] = set()
    for item in assertion_types:
        if item == "vendor_confirmed":
            # Legacy Siemens rows meant vulnerability authority, not exploitation.
            continue
        if item == "exploitation_directly_observed":
            out.add("researcher_exploitation_observed")
            continue
        if item == "exploitation_reported":
            out.add("media_exploitation_reported")
            continue
        if item in EXPLOITATION_ASSERTION_TYPES or item in {
            "vendor_exploitation_confirmed",
            "researcher_exploitation_observed",
            "researcher_catalogued",
            "media_exploitation_reported",
            "government_catalogued",
            "claim_withdrawn",
            "evidence_conflicting",
        }:
            out.add(item)
    return out


def derive_exploitation_state(assertion_types: set[str]) -> tuple[str, str]:
    """Derive cluster exploitation state from exploitation assertions only.

    Vendor vulnerability confirmation alone never yields ``vendor_confirmed``.
    ``vendor_confirmed`` requires an explicit vendor exploitation confirmation.
    """
    types = _normalize_exploitation_types(set(assertion_types))
    if "claim_withdrawn" in types and (
        "researcher_exploitation_observed" in types or "vendor_exploitation_confirmed" in types
    ):
        return "conflicting", "Withdrawal coexists with observation or vendor exploitation confirmation."
    if "claim_withdrawn" in types:
        return "withdrawn", "A source withdrew a prior exploitation claim."
    if "evidence_conflicting" in types:
        return "conflicting", "Conflicting exploitation assertions remain visible."
    if "government_catalogued" in types:
        return "government_catalogued", "A government catalog lists this CVE as exploited (dated fact)."
    if "vendor_exploitation_confirmed" in types:
        return (
            "vendor_confirmed",
            "An official vendor source explicitly confirms or references known active exploitation.",
        )
    if "researcher_exploitation_observed" in types:
        return (
            "researcher_observed",
            "Exploitation observed by a security researcher. Vendor confirmed the vulnerability, not active exploitation.",
        )
    if "researcher_catalogued" in types:
        return (
            "researcher_observed",
            "A research catalog lists reported exploitation with citations. Not CISA KEV and not vendor exploitation confirmation.",
        )
    if "media_exploitation_reported" in types:
        return "media_reported", "Media discovery reported exploitation language; not authoritative confirmation."
    # Vulnerability-only vendor facts (including legacy vendor_confirmed) → not_reported.
    if "vendor_vulnerability_confirmed" in assertion_types or "vendor_confirmed" in assertion_types:
        return "not_reported", "Vendor advisory confirms the vulnerability; exploitation observation is not recorded."
    return "unknown", "Insufficient typed assertions to classify exploitation state."


def upsert_document(db: Session, document: dict[str, Any]) -> tuple[IntelligenceSourceDocument, bool]:
    digest = content_hash(document)
    existing = db.scalar(
        select(IntelligenceSourceDocument).where(
            IntelligenceSourceDocument.source_key == document["source_key"],
            IntelligenceSourceDocument.external_id == document["external_id"],
        )
    )
    now = datetime.now(UTC)
    if existing is None:
        row = IntelligenceSourceDocument(
            id=uuid.uuid4(),
            source_key=document["source_key"],
            source_role=document["source_role"],
            external_id=document["external_id"],
            canonical_url=document.get("canonical_url"),
            title=document["title"],
            published_at=document.get("published_at"),
            source_updated_at=document.get("source_updated_at"),
            first_collected_at=now,
            last_collected_at=now,
            content_hash=digest,
            metadata_safe=document.get("metadata_safe") or {},
            maturity="live_collectable" if document["source_key"] != "fixture" else "fixture_tested",
            correction_state="current",
            parser_version=document["parser_version"],
        )
        db.add(row)
        db.flush()
        _store_assertions(db, row, document.get("assertions") or [])
        return row, True
    changed = existing.content_hash != digest
    existing.last_collected_at = now
    existing.title = document["title"]
    existing.canonical_url = document.get("canonical_url")
    existing.published_at = document.get("published_at") or existing.published_at
    existing.source_updated_at = document.get("source_updated_at") or existing.source_updated_at
    existing.metadata_safe = document.get("metadata_safe") or {}
    existing.parser_version = document["parser_version"]
    existing.updated_at = now
    if changed:
        existing.content_hash = digest
        for old in list(
            db.scalars(select(IntelligenceAssertion).where(IntelligenceAssertion.document_id == existing.id))
        ):
            db.delete(old)
        db.flush()
        _store_assertions(db, existing, document.get("assertions") or [])
    db.flush()
    return existing, changed


def _store_assertions(db: Session, document: IntelligenceSourceDocument, assertions: list[dict[str, Any]]) -> None:
    for item in assertions:
        db.add(
            IntelligenceAssertion(
                id=uuid.uuid4(),
                document_id=document.id,
                subject_key=str(item["subject_key"])[:256],
                assertion_type=str(item["assertion_type"])[:64],
                value=item.get("value") or {},
                observed_at=item.get("observed_at"),
                effective_at=item.get("effective_at") or item.get("observed_at"),
                source_role=document.source_role,
                parser_version=document.parser_version,
                provenance={"source_key": document.source_key, "external_id": document.external_id},
                limitations=item.get("limitations") or [],
            )
        )


def link_cluster(
    db: Session,
    *,
    cve: str,
    document: IntelligenceSourceDocument,
    title: str | None = None,
) -> IntelligenceCluster:
    cluster = db.scalar(
        select(IntelligenceCluster).where(
            IntelligenceCluster.primary_key_type == "cve",
            IntelligenceCluster.primary_key_value == cve,
        )
    )
    if cluster is None:
        cluster = IntelligenceCluster(
            id=uuid.uuid4(),
            primary_key_type="cve",
            primary_key_value=cve,
            title=(title or cve)[:500],
            exploitation_state="unknown",
            exploitation_explanation="",
            aliases={},
            maturity="fixture_tested",
        )
        db.add(cluster)
        db.flush()
    link = db.scalar(
        select(IntelligenceClusterDocument).where(
            IntelligenceClusterDocument.cluster_id == cluster.id,
            IntelligenceClusterDocument.document_id == document.id,
        )
    )
    if link is None:
        db.add(
            IntelligenceClusterDocument(
                id=uuid.uuid4(),
                cluster_id=cluster.id,
                document_id=document.id,
            )
        )
    _refresh_cluster_state(db, cluster)
    return cluster


def _refresh_cluster_state(db: Session, cluster: IntelligenceCluster) -> None:
    doc_ids = list(
        db.scalars(
            select(IntelligenceClusterDocument.document_id).where(IntelligenceClusterDocument.cluster_id == cluster.id)
        )
    )
    types = set(
        db.scalars(
            select(IntelligenceAssertion.assertion_type).where(IntelligenceAssertion.document_id.in_(doc_ids))
        )
    ) if doc_ids else set()
    state, explanation = derive_exploitation_state(types)
    old = {"state": cluster.exploitation_state, "explanation": cluster.exploitation_explanation}
    cluster.exploitation_state = state
    cluster.exploitation_explanation = explanation
    cluster.updated_at = datetime.now(UTC)
    if old["state"] != state:
        digest = hashlib.sha256(f"{old['state']}->{state}:{RULESET_VERSION}".encode()).hexdigest()
        db.add(
            IntelligenceChangeEvent(
                id=uuid.uuid4(),
                cluster_id=cluster.id,
                change_type="exploitation_state_changed",
                materiality_reason=f"Exploitation state moved from {old['state']} to {state}.",
                old_evidence=old,
                new_evidence={"state": state, "explanation": explanation, "ruleset_version": RULESET_VERSION},
                source_key="cluster-derivation",
                evidence_hash=digest,
                ruleset_version=RULESET_VERSION,
            )
        )


def recompute_cluster_states(db: Session, *, cve: str | None = None) -> list[dict[str, str]]:
    """Recompute derived exploitation states without deleting provenance."""
    query = select(IntelligenceCluster)
    if cve:
        query = query.where(
            IntelligenceCluster.primary_key_type == "cve",
            IntelligenceCluster.primary_key_value == cve,
        )
    results: list[dict[str, str]] = []
    for cluster in db.scalars(query):
        before = cluster.exploitation_state
        _refresh_cluster_state(db, cluster)
        results.append(
            {
                "cve": cluster.primary_key_value,
                "before": before,
                "after": cluster.exploitation_state,
            }
        )
    return results


def remap_legacy_assertion_types(db: Session) -> dict[str, int]:
    """Rename legacy assertion types in place; preserve row ids and documents."""
    counts = {"vendor_vulnerability_confirmed": 0, "researcher_exploitation_observed": 0, "media_exploitation_reported": 0}
    for row in db.scalars(select(IntelligenceAssertion).where(IntelligenceAssertion.assertion_type == "vendor_confirmed")):
        # Only remap when value does not already claim exploitation confirmation.
        value = row.value or {}
        if value.get("exploitation_confirmed") is True:
            row.assertion_type = "vendor_exploitation_confirmed"
        else:
            row.assertion_type = "vendor_vulnerability_confirmed"
            counts["vendor_vulnerability_confirmed"] += 1
    for row in db.scalars(
        select(IntelligenceAssertion).where(IntelligenceAssertion.assertion_type == "exploitation_directly_observed")
    ):
        row.assertion_type = "researcher_exploitation_observed"
        counts["researcher_exploitation_observed"] += 1
    for row in db.scalars(
        select(IntelligenceAssertion).where(IntelligenceAssertion.assertion_type == "exploitation_reported")
    ):
        row.assertion_type = "media_exploitation_reported"
        counts["media_exploitation_reported"] += 1
    db.flush()
    return counts


def record_material_change(
    db: Session,
    *,
    cluster: IntelligenceCluster,
    change_type: str,
    reason: str,
    source_key: str,
    old_evidence: dict[str, Any],
    new_evidence: dict[str, Any],
) -> IntelligenceChangeEvent:
    blob = json.dumps({"old": old_evidence, "new": new_evidence}, sort_keys=True, default=str)
    row = IntelligenceChangeEvent(
        id=uuid.uuid4(),
        cluster_id=cluster.id,
        change_type=change_type,
        materiality_reason=reason,
        old_evidence=old_evidence,
        new_evidence=new_evidence,
        source_key=source_key,
        evidence_hash=hashlib.sha256(blob.encode()).hexdigest(),
        ruleset_version=RULESET_VERSION,
    )
    db.add(row)
    db.flush()
    return row
