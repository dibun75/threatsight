"""Deterministic recommendation engine. No automatic execution."""

from __future__ import annotations

import hashlib
import json
import uuid
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import GraphNode, GraphSnapshot, GraphServiceMembership
from threatsight_api.persistence.readiness_models import (
    ReadinessPolicy,
    ReadinessRecommendation,
    ReadinessTrigger,
)
from threatsight_api.readiness import RULESET_VERSION
from threatsight_api.readiness.checks import require_check

CHAIN_CHECKS = {
    "synthetic.fixture:service:customer-ordering": {
        "asset": "synthetic.fixture:device:exact-widget",
        "control": "Validate the installed version",
        "check_id": "synthetic.version.validate.v1",
        "classification": "confirmed_identifier_match",
        "rationale": "An identifier match names ordering-widget under Customer ordering. The installed version still needs validation.",
    },
    "synthetic.fixture:service:privileged-administration": {
        "asset": "meraki.dashboard:device:meraki-ap",
        "control": "Review privileged group membership",
        "check_id": "entra.privileged_assignment.direct.v1",
        "classification": "version_supported_candidate",
        "rationale": "A version-supported candidate names privileged-access-gateway under Privileged administration. Privileged assignment evidence remains unobserved.",
    },
    "synthetic.fixture:service:remote-access": {
        "asset": "junos.device:device:junos-edge",
        "control": "Review the remote-access peer configuration",
        "check_id": "junos.version.recorded.v1",
        "classification": "unknown",
        "rationale": "Remote access records software that cannot be ordered against the advisory. Recorded VPN and software configuration still need validation. Observed reachability remains unknown.",
    },
}


def ensure_policy(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID) -> ReadinessPolicy:
    row = db.scalar(select(ReadinessPolicy).where(ReadinessPolicy.workspace_id == workspace_id))
    if row is not None:
        return row
    row = ReadinessPolicy(tenant_id=tenant_id, workspace_id=workspace_id)
    db.add(row)
    db.flush()
    return row


def evidence_hash(*parts: object) -> str:
    blob = json.dumps(parts, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def recommend_for_workspace(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, *, actor: str = "system") -> dict:
    policy = ensure_policy(db, tenant_id, workspace_id)
    snapshot = db.scalar(
        select(GraphSnapshot).where(
            GraphSnapshot.tenant_id == tenant_id,
            GraphSnapshot.workspace_id == workspace_id,
            GraphSnapshot.is_current.is_(True),
        )
    )
    if snapshot is None:
        return {"triggers": 0, "recommendations": 0, "status": "needs_more_data"}
    created_triggers = 0
    created_recommendations = 0
    for service_key, spec in CHAIN_CHECKS.items():
        service = db.scalar(
            select(GraphNode).where(
                GraphNode.snapshot_id == snapshot.id,
                GraphNode.workspace_id == workspace_id,
                GraphNode.source_key == service_key,
            )
        )
        if service is None:
            continue
        member = db.scalar(
            select(GraphServiceMembership).where(
                GraphServiceMembership.workspace_id == workspace_id,
                GraphServiceMembership.service_node_id == service.id,
            )
        )
        asset = None
        if member is not None:
            asset = db.get(GraphNode, member.member_node_id)
        if asset is None or asset.source_key != spec["asset"]:
            # Membership may store the asset; fall back to source key lookup.
            asset = db.scalar(
                select(GraphNode).where(
                    GraphNode.snapshot_id == snapshot.id,
                    GraphNode.workspace_id == workspace_id,
                    GraphNode.source_key == spec["asset"],
                )
            )
        if asset is None:
            continue
        check = require_check(spec["check_id"])
        digest = evidence_hash(service_key, asset.source_key, spec["check_id"], snapshot.id, RULESET_VERSION)
        trigger_key = f"trigger:{service_key}:{digest[:16]}"
        existing_trigger = db.scalar(
            select(ReadinessTrigger).where(
                ReadinessTrigger.workspace_id == workspace_id,
                ReadinessTrigger.external_key == trigger_key,
            )
        )
        if existing_trigger is None:
            if created_recommendations >= policy.max_recommendations_per_trigger * 3:
                break
            existing_trigger = ReadinessTrigger(
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                external_key=trigger_key,
                reason_code="changed_correlation_evidence",
                summary=spec["rationale"][:500],
                service_source_key=service_key,
                service_node_id=service.id,
                snapshot_id=snapshot.id,
                evidence_hash=digest,
                maturity="fixture_tested",
                provenance={"ruleset": RULESET_VERSION, "actor": actor},
            )
            db.add(existing_trigger)
            db.flush()
            created_triggers += 1
            _audit(db, tenant_id, workspace_id, "trigger", existing_trigger.id, "created", actor, {"service": service_key})
        rec_key = f"recommendation:{service_key}:{check.id}:{digest[:16]}"
        existing_rec = db.scalar(
            select(ReadinessRecommendation).where(
                ReadinessRecommendation.workspace_id == workspace_id,
                ReadinessRecommendation.external_key == rec_key,
            )
        )
        if existing_rec is not None:
            if existing_rec.evidence_hash != digest and existing_rec.state not in {"dismissed", "superseded"}:
                replacement = ReadinessRecommendation(
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    trigger_id=existing_trigger.id,
                    external_key=f"{rec_key}:reopen:{existing_rec.version + 1}",
                    state="candidate",
                    service_source_key=service_key,
                    service_node_id=service.id,
                    asset_source_key=asset.source_key,
                    asset_node_id=asset.id,
                    control_title=spec["control"],
                    check_id=check.id,
                    check_version=check.version,
                    match_classification=spec["classification"],
                    rationale=spec["rationale"],
                    evidence_hash=digest,
                    ruleset_version=RULESET_VERSION,
                    maturity="fixture_tested",
                    version=existing_rec.version + 1,
                )
                db.add(replacement)
                db.flush()
                existing_rec.state = "superseded"
                existing_rec.superseded_by_id = replacement.id
                existing_rec.version += 1
                created_recommendations += 1
            continue
        recommendation = ReadinessRecommendation(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            trigger_id=existing_trigger.id,
            external_key=rec_key,
            state="candidate",
            service_source_key=service_key,
            service_node_id=service.id,
            asset_source_key=asset.source_key,
            asset_node_id=asset.id,
            control_title=spec["control"],
            check_id=check.id,
            check_version=check.version,
            match_classification=spec["classification"],
            rationale=spec["rationale"],
            evidence_hash=digest,
            ruleset_version=RULESET_VERSION,
            maturity="fixture_tested",
        )
        db.add(recommendation)
        db.flush()
        created_recommendations += 1
        _audit(db, tenant_id, workspace_id, "recommendation", recommendation.id, "created", actor, {"check_id": check.id})
    db.flush()
    return {"triggers": created_triggers, "recommendations": created_recommendations, "status": "ok", "ruleset": RULESET_VERSION}


def _audit(db: Session, tenant_id: uuid.UUID, workspace_id: uuid.UUID, object_type: str, object_id: uuid.UUID, action: str, actor: str, payload: dict) -> None:
    from threatsight_api.persistence.readiness_models import ReadinessAudit

    db.add(
        ReadinessAudit(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            object_type=object_type,
            object_id=object_id,
            action=action,
            actor=actor,
            payload=payload,
        )
    )
