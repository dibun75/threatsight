"""Idempotent Warehouse automation exploitation assessment exercise."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.persistence.models import Identity, Workspace, WorkspaceMembership
from threatsight_api.persistence.multisource_models import IntelligenceCluster
from threatsight_api.persistence.readiness_models import ReadinessAction
from threatsight_api.persistence.response_models import (
    ResponseJurisdictionProfile,
    ResponseWorkspace,
)
from threatsight_api.response import service as response_service
from threatsight_api.response.vocabulary import JURISDICTION_NIS2_NO_KEY
from threatsight_api.signing.reference import ensure_reference_signature

EXERCISE_KEY = "warehouse-automation-exploitation-assessment"
EXERCISE_TITLE = "Warehouse automation exploitation assessment"
ACTOR = "reference:phase3e"
CVE = "CVE-2026-58115"


def install(connection) -> None:
    session = Session(bind=connection)
    try:
        # Limit reference exercise to the primary demo workspace and explicit synthetic demos.
        workspaces = list(
            session.scalars(
                select(Workspace).where(
                    Workspace.status == "active",
                    (Workspace.key == "default") | (Workspace.classification == "synthetic_demo"),
                )
            )
        )
        for workspace in workspaces:
            install_workspace(session, workspace)
        session.commit()
    finally:
        session.close()


def install_workspace(db: Session, workspace: Workspace) -> ResponseWorkspace | None:
    existing = db.scalar(
        select(ResponseWorkspace).where(
            ResponseWorkspace.workspace_id == workspace.id,
            ResponseWorkspace.stable_key == EXERCISE_KEY,
        )
    )
    if existing is not None and existing.lifecycle == "closed":
        # Second run: already complete — no duplicates
        return existing

    owner = _synthetic_identity(db, workspace, "response-lead-warehouse", "Synthetic Response Lead")
    tech = _synthetic_identity(db, workspace, "response-tech-warehouse", "Synthetic Technical Lead")
    scribe = _synthetic_identity(db, workspace, "response-scribe-warehouse", "Synthetic Scribe")

    if existing is None:
        detail = response_service.propose(
            db,
            workspace.tenant_id,
            workspace.id,
            actor=ACTOR,
            role="workspace-admin",
            title=EXERCISE_TITLE,
            reason=(
                "External researcher observation of CVE-2026-58115 plus Siemens vulnerability confirmation "
                "and a synthetic IoT2050 product match. Device version, Node-RED, authentication, and "
                "reachability are unknown. No customer compromise evidence exists."
            ),
            mode="exercise",
            stable_key=EXERCISE_KEY,
            idempotency_key=f"phase3e-{EXERCISE_KEY}",
            known_facts=(
                "CVE-2026-58115 is researcher-observed externally. "
                "Siemens confirms vulnerability facts (vendor_vulnerability_confirmed). "
                "Synthetic IoT2050 product match exists for warehouse automation."
            ),
            uncertain_facts=(
                "Device version unknown. Node-RED state unknown. Authentication state unknown. "
                "Reachability unknown. No customer compromise evidence."
            ),
            operational_impact="Potential warehouse automation OT exposure pending verification; not a confirmed incident.",
            is_synthetic=True,
            services=[
                {
                    "service_key": "synthetic.fixture:service:warehouse-automation",
                    "service_name": "Warehouse automation",
                    "involvement": "potentially_affected",
                    "notes": "Synthetic exercise service — not a live customer claim.",
                }
            ],
        )
        response_id = uuid.UUID(detail["id"])
    else:
        response_id = existing.id

    row = db.get(ResponseWorkspace, response_id)
    assert row is not None

    if row.lifecycle == "draft":
        response_service.activate(
            db,
            workspace.tenant_id,
            workspace.id,
            row.id,
            actor=ACTOR,
            role="workspace-admin",
            rationale="Activate as synthetic exercise for warehouse OT verification practice. Not a confirmed incident.",
            mode="exercise",
            expected_version=row.version,
        )
        row = db.get(ResponseWorkspace, response_id)

    # Roles (idempotent — assign_role deactivates prior same role+identity)
    for role_key, identity in (
        ("response_lead", owner),
        ("technical_lead", tech),
        ("scribe", scribe),
        ("evidence_coordinator", owner),
    ):
        response_service.assign_role(
            db,
            workspace.tenant_id,
            workspace.id,
            row.id,
            actor=ACTOR,
            role="workspace-admin",
            role_key=role_key,
            identity_id=identity.id,
            notes="Synthetic exercise identity",
        )

    # Link verification actions (reuse readiness_actions; create context actions if missing)
    for external_key, title, required in (
        (
            "resp-ex-verify-product-version",
            "Verify IoT2050 product/version",
            "Record installed product version against Siemens advisory",
        ),
        (
            "resp-ex-verify-node-red",
            "Confirm Node-RED feature/prerequisite state",
            "Determine whether Node-RED is enabled",
        ),
        (
            "resp-ex-determine-reachability",
            "Determine reachability",
            "Assess network exposure of the device",
        ),
        (
            "resp-ex-preserve-evidence",
            "Preserve evidence references",
            "Pin intelligence and readiness artifacts",
        ),
    ):
        action = db.scalar(
            select(ReadinessAction).where(
                ReadinessAction.workspace_id == workspace.id,
                ReadinessAction.external_key == external_key,
            )
        )
        if action is None:
            action = ReadinessAction(
                id=uuid.uuid4(),
                tenant_id=workspace.tenant_id,
                workspace_id=workspace.id,
                external_key=external_key,
                status="assigned",
                priority="high",
                title=title,
                why="Synthetic exercise verification step for CVE-2026-58115 warehouse assessment.",
                what_changed="Researcher-observed CVE with Siemens vulnerability confirmation",
                required_work=required,
                evidence_required="Operator-recorded verification note",
                known="CVE researcher-observed; Siemens vulnerability confirmed; synthetic product match",
                uncertain="Version, Node-RED, auth, reachability, compromise — all unknown",
                closure_guidance="Close only with explicit verification evidence. Not remediation.",
                service_source_key="synthetic.fixture:service:warehouse-automation",
                control_title="OT verification",
                owner_identity_id=tech.id,
                owner_subject=tech.subject,
                assigned_by=ACTOR,
                assigned_at=datetime.now(UTC),
                due_at=datetime.now(UTC) + timedelta(days=7),
                maturity="fixture_tested",
                metadata_safe={"synthetic_exercise": True, "cve": CVE},
            )
            db.add(action)
            db.flush()
        response_service.link_action(
            db,
            workspace.tenant_id,
            workspace.id,
            row.id,
            actor=ACTOR,
            role="workspace-admin",
            action_id=action.id,
            response_role="technical_lead",
            notes="Exercise verification action",
        )

    # Intelligence / evidence pins
    cluster = db.scalar(
        select(IntelligenceCluster).where(
            IntelligenceCluster.primary_key_type == "cve",
            IntelligenceCluster.primary_key_value == CVE,
        )
    )
    if cluster is not None:
        response_service.link_intelligence(
            db,
            workspace.tenant_id,
            workspace.id,
            row.id,
            actor=ACTOR,
            role="workspace-admin",
            link_type="intelligence_cluster",
            target_id=cluster.id,
            label=CVE,
            evidence_assessment="supported",
            notes="Researcher-observed externally; not compromise evidence",
        )
        response_service.pin_evidence(
            db,
            workspace.tenant_id,
            workspace.id,
            row.id,
            actor=ACTOR,
            role="workspace-admin",
            ref_kind="intelligence_cluster",
            ref_id=cluster.id,
            label=f"{CVE} cluster",
            evidence_assessment="supported",
        )

    response_service.add_timeline_entry(
        db,
        workspace.tenant_id,
        workspace.id,
        row.id,
        actor=ACTOR,
        role="workspace-admin",
        category="verification_result",
        summary="Exercise baseline: no customer compromise evidence; verification actions open.",
        evidence_state="not_supported",
    )

    response_service.add_decision(
        db,
        workspace.tenant_id,
        workspace.id,
        row.id,
        actor=ACTOR,
        role="workspace-admin",
        decision="Needs more data",
        rationale=(
            "Version, Node-RED, authentication, and reachability remain unknown. "
            "Do not declare an incident. Continue verification."
        ),
        evidence_considered="Researcher observation; Siemens vulnerability confirmation; synthetic product match",
        alternatives="Declare suspected incident; rule out; continue exercise verification",
        remaining_uncertainty="Device version, Node-RED, auth, reachability, compromise evidence",
        idempotency_key=f"{EXERCISE_KEY}-needs-more-data",
        review_at=datetime.now(UTC) + timedelta(days=3),
    )

    sitrep = response_service.create_sitrep(
        db,
        workspace.tenant_id,
        workspace.id,
        row.id,
        actor=ACTOR,
        role="workspace-admin",
        fields={
            "current_status": "Synthetic exercise activated. Assessment ongoing. No incident declared.",
            "what_changed": "External CVE observation and Siemens vulnerability confirmation with synthetic product match.",
            "business_services": "Warehouse automation (synthetic)",
            "known_facts": row.known_facts,
            "uncertain_facts": row.uncertain_facts,
            "actions_and_owners": "Verification actions assigned to synthetic technical lead",
            "decisions_required": "None for declaration; continue verification",
            "evidence_freshness": "Reference intelligence as of exercise load",
            "external_communication_state": "No external messages; drafts only if created",
            "regulatory_assessment_state": "not_determined — informational profile available",
        },
    )
    response_service.finalize_sitrep(
        db,
        workspace.tenant_id,
        workspace.id,
        row.id,
        uuid.UUID(sitrep["id"]),
        actor=ACTOR,
        role="workspace-admin",
    )

    response_service.create_comm_draft(
        db,
        workspace.tenant_id,
        workspace.id,
        row.id,
        actor=ACTOR,
        role="workspace-admin",
        template_key="executive_update",
        subject="Draft — Warehouse automation exercise update",
        body_text=(
            "Draft — not sent.\n\n"
            "This is a synthetic exercise. CVE-2026-58115 is under assessment. "
            "No confirmed incident. No compromise evidence. Verification in progress."
        ),
    )

    profile = db.scalar(
        select(ResponseJurisdictionProfile).where(ResponseJurisdictionProfile.profile_key == JURISDICTION_NIS2_NO_KEY)
    )
    if profile is not None:
        response_service.upsert_regulatory(
            db,
            workspace.tenant_id,
            workspace.id,
            row.id,
            actor=ACTOR,
            role="workspace-admin",
            profile_id=profile.id,
            legal_applicability="not_determined",
            reporting_obligation="not_determined",
            evidence_notes="Exercise only — applicability not determined. Not legal advice.",
        )

    snap = response_service.create_snapshot(
        db,
        workspace.tenant_id,
        workspace.id,
        row.id,
        actor=ACTOR,
        role="workspace-admin",
        idempotency_key=f"{EXERCISE_KEY}-snapshot-v1",
    )
    # Attempt reference sign via linked action when local key available
    if snap.get("action_id"):
        action = db.get(ReadinessAction, uuid.UUID(snap["action_id"]))
        if action is not None:
            ensure_reference_signature(db, workspace, action, ACTOR)

    row = db.get(ResponseWorkspace, response_id)
    assert row is not None
    if row.lifecycle != "closed":
        response_service.close_response(
            db,
            workspace.tenant_id,
            workspace.id,
            row.id,
            actor=ACTOR,
            role="workspace-admin",
            notes="Exercise closed. Lessons: keep known vs uncertain distinct; never auto-declare incidents.",
            lessons_learned=(
                "Activation and declaration remain separate. Verification actions stay open for follow-up. "
                "Synthetic exercise must never be presented as a confirmed incident."
            ),
            expected_version=row.version,
        )
    return db.get(ResponseWorkspace, response_id)


def _synthetic_identity(db: Session, workspace: Workspace, subject_suffix: str, display_name: str) -> Identity:
    subject = f"synthetic:{subject_suffix}"
    identity = db.scalar(select(Identity).where(Identity.issuer == "synthetic-reference", Identity.subject == subject))
    if identity is None:
        identity = Identity(
            id=uuid.uuid4(),
            issuer="synthetic-reference",
            subject=subject,
            display_name=display_name,
            email=None,
            status="active",
        )
        db.add(identity)
        db.flush()
    membership = db.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.subject == subject,
        )
    )
    if membership is None:
        db.add(
            WorkspaceMembership(
                id=uuid.uuid4(),
                workspace_id=workspace.id,
                subject=subject,
                identity_id=identity.id,
                role="operator",
            )
        )
        db.flush()
    elif membership.identity_id is None:
        membership.identity_id = identity.id
        db.flush()
    return identity
