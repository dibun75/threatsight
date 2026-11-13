from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import delete as sql_delete
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.assurance.engine import (
    DEMO_ENVIRONMENT,
    DEMO_SYSTEM_NAME,
    bootstrap_demo as bootstrap_assurance,
    execute_run,
)
from threatsight_api.config import Settings
from threatsight_api.discovery.engine import bootstrap_demo as bootstrap_discovery
from threatsight_api.domain.enums import (
    AssuranceStatus,
    AuditAction,
    EvidenceStatus,
    EvidenceType,
    LifecycleStatus,
    RecordOrigin,
)
from threatsight_api.services.identity import (
    KNOWLEDGE_SYSTEM_NAME,
    SHOWCASE_DISPLAY_NAME,
    SHOWCASE_ORG,
)
from threatsight_api.frameworks.engine import bootstrap_frameworks
from threatsight_api.persistence.models import (
    AgentEvent,
    AISystemProfile,
    AISystemRecord,
    AssuranceRunRecord,
    ControlRecord,
    EvidenceControlLink,
    EvidenceRecord,
    EvidenceSystemLink,
    IntelligenceRun,
)
from threatsight_api.services.audit import record_audit
from threatsight_api.threats.engine import bootstrap_intel

ATTESTATION_REF = "m10-labelled-attestation"
DEMO_EVENT_CORRELATION = "m13-labelled-cancel-order"

STATIC_WALKTHROUGH = [
    {
        "id": "overview",
        "title": "Executive overview",
        "href": "/",
        "group": "primary",
        "why": "Counts, data origin, and the executive summary come from Postgres. Zeros are honest. This is not a legal compliance result.",
    },
    {
        "id": "inventory",
        "title": "AI systems",
        "href": "/systems",
        "group": "primary",
        "why": "Customer Support AI Assistant is the in-scope system. Order support demo is the technical identifier, not a second enterprise system.",
    },
    {
        "id": "requirements",
        "title": "Requirements",
        "href": "/requirements",
        "group": "primary",
        "why": "Requirements map to controls. Extracted items stay candidates until human review.",
    },
    {
        "id": "controls",
        "title": "Controls",
        "href": "/controls",
        "group": "primary",
        "why": "The control is the central object. Technical verdicts come from tests, not from an LLM.",
    },
    {
        "id": "evidence",
        "title": "Evidence",
        "href": "/evidence",
        "group": "primary",
        "why": "Manual attestations and hashed CTRL-002 envelopes. Freshness uses real timestamps.",
    },
    {
        "id": "tests",
        "title": "Assurance tests",
        "href": "/assurance",
        "group": "primary",
        "why": "AUTH-01 remains a confirmed, sandboxed run against the demo agent.",
    },
    {
        "id": "findings",
        "title": "Findings",
        "href": "/findings",
        "group": "primary",
        "why": "FAIL is observed impact, not narration.",
    },
    {
        "id": "remediation",
        "title": "Remediation",
        "href": "/assurance",
        "group": "primary",
        "why": "Gateway remediation is an explicit operator action on the synthetic agent.",
    },
    {
        "id": "retest",
        "title": "Retest",
        "href": "/assurance",
        "group": "primary",
        "why": "AUTH-02 is a parent-linked retest. It does not rewrite history.",
    },
    {
        "id": "frameworks",
        "title": "Informational framework maps",
        "href": "/frameworks",
        "group": "supporting",
        "why": "Curated incomplete mappings. Not a legal compliance claim.",
    },
    {
        "id": "intelligence",
        "title": "Threat intelligence",
        "href": "/threats",
        "group": "supporting",
        "why": "Curated techniques suggest tests. There is no crawl or exploit engine.",
    },
    {
        "id": "discovery",
        "title": "Authorized discovery",
        "href": "/discovery",
        "group": "supporting",
        "why": "The synthetic demo site is registered. A scan still requires confirm_execution.",
    },
    {
        "id": "matrix",
        "title": "Control matrix export",
        "href": "/exports",
        "group": "supporting",
        "why": "Control | Requirement | Test | Result | Evidence | Owner | Framework | Freshness.",
    },
    {
        "id": "explain",
        "title": "Executive explanation",
        "href": "/",
        "group": "supporting",
        "why": "Evidence-linked posture explanation. An LLM may summarize; it never authorizes or claims legal compliance.",
    },
]


SHOWCASE_SCENARIO = {
    "company": "Nordic Retail AS",
    "ai_system": "Customer Support AI Assistant",
    "inventory_name": DEMO_SYSTEM_NAME,
    "purpose": "Handles customer questions and order changes.",
    "risk": "AI agent can perform business actions.",
    "control": "AI agents must not execute unauthorized business operations.",
    "control_identifier": "CTRL-002",
    "threat": "unauthorized tool execution",
    "ops_chain": "policy → CTRL-002 → unauthorized tool execution → AUTH-01 FAIL → remediate → AUTH-02 PASS → executive explanation",
    "labelled_synthetic": True,
    "legal_compliance_claim": False,
}

GUIDED_STORY = [
    {
        "id": "system",
        "title": "Example AI system",
        "href": "/systems",
        "body": "Nordic Retail AS operates Customer Support AI Assistant. Demonstrated capability: order support. Technical identifier: Order support demo. Labelled synthetic, not a second enterprise system, not live enterprise discovery.",
    },
    {
        "id": "risk",
        "title": "Existing risk",
        "href": "/threats",
        "body": "The assistant can change orders. CTRL-002 requires unauthorized business operations to be denied by a gateway, not by model narration.",
    },
    {
        "id": "failure",
        "title": "Control failure",
        "href": "/assurance",
        "body": "Confirm AUTH-01. The synthetic agent completes unauthorized cancel_order. FAIL is observed impact.",
    },
    {
        "id": "evidence",
        "title": "Evidence",
        "href": "/evidence",
        "body": "The run writes a hashed observation envelope. The manual attestation is labelled synthetic.",
    },
    {
        "id": "remediation",
        "title": "Remediation",
        "href": "/assurance",
        "body": "Close the synthetic gateway. That is an explicit operator action on the demo agent.",
    },
    {
        "id": "retest",
        "title": "Successful retest",
        "href": "/assurance",
        "body": "Confirm AUTH-02 as a parent-linked retest. History is not rewritten.",
    },
    {
        "id": "explain",
        "title": "Executive explanation",
        "href": "/",
        "body": "Explain my posture cites systems, CTRL-002, unauthorized tool execution, FAIL, remediation, and retest. An LLM may summarize; it never authorizes and never claims legal compliance.",
    },
]


def showcase_status(settings: Settings) -> dict:
    return {
        "milestone": settings.milestone,
        "legal_compliance_claim": False,
        "llm_authors_executive_summary": False,
        "synthetic_demo_labelled": True,
        "autonomous_attack": False,
        "exploitation_engine": False,
        "framework_catalog_complete": False,
        "intel_catalog_complete": False,
        "unrestricted_crawl": False,
        "confirm_execution_required_for_auth01": True,
        "evidence_fresh_days": settings.evidence_fresh_days,
        "scenario": dict(SHOWCASE_SCENARIO),
        "walkthrough": list(STATIC_WALKTHROUGH),
        "guided_story": list(GUIDED_STORY),
        "primary_loop": [item["id"] for item in STATIC_WALKTHROUGH if item["group"] == "primary"],
    }


def _walkthrough_with_ids(assurance: dict, discovery: dict, extra: dict, run) -> list[dict]:
    system_id = assurance.get("system_id")
    control_id = assurance.get("control_id")
    evidence_id = extra.get("attestation_evidence_id")
    finding_id = str(run.finding_id) if run is not None and getattr(run, "finding_id", None) else None
    steps = []
    for item in STATIC_WALKTHROUGH:
        step = dict(item)
        if item["id"] == "inventory" and system_id:
            step["href"] = f"/systems/{system_id}"
        if item["id"] == "controls" and control_id:
            step["href"] = f"/controls/{control_id}"
        if item["id"] == "evidence" and evidence_id:
            step["href"] = f"/evidence/{evidence_id}"
        if item["id"] in {"findings", "remediation"} and finding_id:
            step["href"] = f"/findings/{finding_id}"
        if item["id"] == "discovery" and discovery.get("source_id"):
            step["href"] = "/discovery"
        steps.append(step)
    return steps


def seed_labelled_records(db: Session, actor: str, *, control_id: str, order_system_id: str) -> dict:
    control = db.get(ControlRecord, UUID(str(control_id)))
    order_system = db.get(AISystemRecord, UUID(str(order_system_id)))
    knowledge = db.scalar(
        select(AISystemRecord).where(
            AISystemRecord.name == KNOWLEDGE_SYSTEM_NAME,
            AISystemRecord.environment == DEMO_ENVIRONMENT,
        )
    )
    if knowledge is None:
        knowledge = AISystemRecord(
            name=KNOWLEDGE_SYSTEM_NAME,
            description="Labelled synthetic supporting inventory for the Nordic Retail portfolio. Not a second enterprise system.",
            owner="platform",
            team="assurance",
            lifecycle=LifecycleStatus.ACTIVE.value,
            risk_classification="internal-demo",
            environment=DEMO_ENVIRONMENT,
            record_origin=RecordOrigin.SHOWCASE.value,
        )
        db.add(knowledge)
        db.flush()
        record_audit(
            db,
            entity_type="ai_system",
            entity_id=knowledge.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={
                "name": KNOWLEDGE_SYSTEM_NAME,
                "environment": DEMO_ENVIRONMENT,
                "synthetic_demo_labelled": True,
                "source": "m10-demo-data",
                "legal_compliance_claim": False,
            },
        )
    else:
        knowledge.record_origin = RecordOrigin.SHOWCASE.value
    attestation = db.scalar(select(EvidenceRecord).where(EvidenceRecord.source_reference == ATTESTATION_REF))
    if attestation is None and control is not None:
        now = datetime.now(UTC)
        attestation = EvidenceRecord(
            title="Labelled gateway policy attestation",
            description="Synthetic operator attestation that CTRL-002 is in scope. Not a test verdict and not a legal conclusion.",
            evidence_type=EvidenceType.MANUAL.value,
            source_reference=ATTESTATION_REF,
            provenance="synthetic-demo",
            collected_at=now,
            owner="security",
            status=EvidenceStatus.SUBMITTED.value,
        )
        db.add(attestation)
        db.flush()
        db.add(EvidenceControlLink(evidence_id=attestation.id, control_id=control.id))
        if order_system is not None:
            db.add(EvidenceSystemLink(evidence_id=attestation.id, ai_system_id=order_system.id))
        record_audit(
            db,
            entity_type="evidence",
            entity_id=attestation.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={
                "source": "m10-demo-data",
                "synthetic_demo_labelled": True,
                "legal_compliance_claim": False,
            },
        )
    extra = seed_ops_records(db, actor, order_system=order_system, knowledge=knowledge)
    return {
        "order_system": DEMO_SYSTEM_NAME,
        "knowledge_system_id": str(knowledge.id) if knowledge is not None else None,
        "attestation_evidence_id": str(attestation.id) if attestation is not None else None,
        "synthetic_demo_labelled": True,
        **extra,
    }


def seed_ops_records(db: Session, actor: str, *, order_system, knowledge) -> dict:
    profile_id = None
    event_id = None
    if order_system is not None:
        profile = db.scalar(select(AISystemProfile).where(AISystemProfile.ai_system_id == order_system.id))
        if profile is None:
            profile = AISystemProfile(
                ai_system_id=order_system.id,
                purpose="Handles customer questions and order changes.",
                data_categories=["order records", "customer contact"],
                users_subjects=["customers", "support operators"],
                capabilities=[
                    {"name": "cancel_order", "kind": "tool"},
                    {"name": "lookup_order", "kind": "tool"},
                ],
                missing=[],
                labelled_synthetic=True,
            )
            db.add(profile)
            db.flush()
            record_audit(
                db,
                entity_type="ai_system_profile",
                entity_id=profile.id,
                action=AuditAction.CREATE,
                actor=actor,
                payload={
                    "source": "m13-ops",
                    "labelled_synthetic": True,
                    "legal_compliance_claim": False,
                },
            )
        profile_id = str(profile.id)
        existing_event = db.scalar(
            select(AgentEvent).where(AgentEvent.correlation_id == DEMO_EVENT_CORRELATION)
        )
        if existing_event is None:
            existing_event = AgentEvent(
                ai_system_id=order_system.id,
                source_kind="gateway",
                agent_id="order-support-demo",
                session_id="lab-session-001",
                user_context="untrusted-user",
                tool_name="cancel_order",
                arguments={"order_id": "ORD-1001"},
                authorization_context={"authorized": False, "actor": "untrusted-user"},
                result_metadata={
                    "completed": True,
                    "labelled_synthetic": True,
                    "enforcement": "none",
                    "runtime_firewall": False,
                },
                occurred_at=datetime.now(UTC),
                correlation_id=DEMO_EVENT_CORRELATION,
                labelled_synthetic=True,
            )
            db.add(existing_event)
            db.flush()
            record_audit(
                db,
                entity_type="agent_event",
                entity_id=existing_event.id,
                action=AuditAction.CREATE,
                actor=actor,
                payload={
                    "source": "m13-ops",
                    "tool_name": "cancel_order",
                    "labelled_synthetic": True,
                    "runtime_firewall": False,
                    "legal_compliance_claim": False,
                },
            )
        event_id = str(existing_event.id)
    if knowledge is not None:
        knowledge_profile = db.scalar(select(AISystemProfile).where(AISystemProfile.ai_system_id == knowledge.id))
        if knowledge_profile is None:
            knowledge_profile = AISystemProfile(
                ai_system_id=knowledge.id,
                purpose="Labelled synthetic inventory system for the portfolio demo.",
                data_categories=[],
                users_subjects=[],
                capabilities=[],
                missing=["data_categories", "users_subjects", "capabilities", "threat mapping"],
                labelled_synthetic=True,
            )
            db.add(knowledge_profile)
            db.flush()
    return {
        "profile_id": profile_id,
        "agent_event_id": event_id,
        "runtime_firewall": False,
    }


def bootstrap_showcase(db: Session, settings: Settings, actor: str, *, confirm_execution: bool) -> dict:
    assurance = bootstrap_assurance(db, settings, actor)
    extra = seed_labelled_records(
        db,
        actor,
        control_id=assurance["control_id"],
        order_system_id=assurance["system_id"],
    )
    frameworks = bootstrap_frameworks(db, actor)
    threats = bootstrap_intel(db, actor)
    discovery = bootstrap_discovery(db, settings, actor)
    run = None
    if confirm_execution:
        run = execute_run(
            db,
            settings,
            scenario_key="AUTH-01",
            actor=actor,
            confirm_execution=True,
        )
    system = db.get(AISystemRecord, UUID(str(assurance["system_id"]))) if assurance.get("system_id") else None
    if system is not None:
        record_audit(
            db,
            entity_type="ai_system",
            entity_id=system.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={
                "source": "m10-showcase",
                "confirm_execution": confirm_execution,
                "legal_compliance_claim": False,
                "synthetic_demo_labelled": True,
                "autonomous_attack": False,
            },
        )
    return {
        "legal_compliance_claim": False,
        "synthetic_demo_labelled": True,
        "llm_authors_executive_summary": False,
        "autonomous_attack": False,
        "executed_auth01": run is not None,
        "confirm_execution": confirm_execution,
        "run_id": str(run.id) if run is not None else None,
        "verdict": run.verdict if run is not None else None,
        "assurance": assurance,
        "inventory": extra,
        "frameworks": frameworks,
        "threats": {key: threats[key] for key in threats if key != "catalog"},
        "discovery": discovery,
        "walkthrough": _walkthrough_with_ids(assurance, discovery, extra, run),
        "guided_story": list(GUIDED_STORY),
        "scenario": dict(SHOWCASE_SCENARIO),
    }


def reset_showcase(
    db: Session,
    settings: Settings,
    actor: str,
    *,
    reseed: bool = True,
    confirm_execution: bool = False,
) -> dict:
    systems = list(
        db.scalars(select(AISystemRecord).where(AISystemRecord.record_origin == RecordOrigin.SHOWCASE.value))
    )
    deleted_names = [item.name for item in systems]
    evidence_ids: set[UUID] = set()
    system_ids = [item.id for item in systems]
    if system_ids:
        for evidence_id in db.scalars(
            select(EvidenceSystemLink.evidence_id).where(EvidenceSystemLink.ai_system_id.in_(system_ids))
        ):
            evidence_ids.add(evidence_id)
        for evidence_id in db.scalars(
            select(AssuranceRunRecord.evidence_id).where(
                AssuranceRunRecord.ai_system_id.in_(system_ids),
                AssuranceRunRecord.evidence_id.is_not(None),
            )
        ):
            if evidence_id is not None:
                evidence_ids.add(evidence_id)
        db.execute(sql_delete(IntelligenceRun).where(IntelligenceRun.source_id.in_(system_ids)))
    attestation = db.scalar(select(EvidenceRecord).where(EvidenceRecord.source_reference == ATTESTATION_REF))
    if attestation is not None:
        evidence_ids.add(attestation.id)
    if system_ids:
        db.execute(sql_delete(AISystemRecord).where(AISystemRecord.id.in_(system_ids)))
    db.flush()
    still_linked = set()
    if evidence_ids:
        still_linked = set(
            db.scalars(select(EvidenceSystemLink.evidence_id).where(EvidenceSystemLink.evidence_id.in_(evidence_ids)))
        )
    to_delete = [item for item in evidence_ids if item not in still_linked]
    deleted_evidence = 0
    if to_delete:
        db.execute(sql_delete(EvidenceRecord).where(EvidenceRecord.id.in_(to_delete)))
        deleted_evidence = len(to_delete)
    db.flush()
    control = db.scalar(select(ControlRecord).where(ControlRecord.identifier == "CTRL-002"))
    if control is not None:
        remaining_run = db.scalar(
            select(AssuranceRunRecord.id).where(AssuranceRunRecord.control_id == control.id).limit(1)
        )
        if remaining_run is None:
            control.latest_verdict = None
            control.assurance_status = AssuranceStatus.EVIDENCE_REQUIRED.value
            control.assurance_rationale = "Awaiting CTRL-002 execution evidence."
    db.flush()
    record_audit(
        db,
        entity_type="showcase",
        entity_id=uuid4(),
        action=AuditAction.DELETE,
        actor=actor,
        payload={
            "source": "m14-showcase-reset",
            "deleted_systems": deleted_names,
            "deleted_evidence": deleted_evidence,
            "origin_filter": RecordOrigin.SHOWCASE.value,
            "legal_compliance_claim": False,
        },
    )
    seeded = None
    if reseed:
        seeded = bootstrap_showcase(db, settings, actor, confirm_execution=confirm_execution)
    return {
        "legal_compliance_claim": False,
        "deleted_systems": len(deleted_names),
        "deleted_names": deleted_names,
        "deleted_evidence": deleted_evidence,
        "origin_filter": RecordOrigin.SHOWCASE.value,
        "unlabelled_records_untouched": True,
        "reseeded": reseed,
        "organisation": SHOWCASE_ORG,
        "ai_system": SHOWCASE_DISPLAY_NAME,
        "bootstrap": seeded,
    }
