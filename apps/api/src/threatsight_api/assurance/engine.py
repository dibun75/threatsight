from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatsight_api.assurance.adapter import TargetAdapter, build_adapter
from threatsight_api.assurance.catalog import AUTH_01, AdapterRequest, CATALOG, CTRL_002, get_scenario
from threatsight_api.assurance.envelope import canonical_envelope, hash_envelope
from threatsight_api.assurance.policy import evaluate_ctrl002
from threatsight_api.assurance.safety import AssuranceSafetyError, assert_execution_allowed
from threatsight_api.config import Settings
from threatsight_api.domain.enums import (
    AssuranceStatus,
    AuditAction,
    ControlSeverity,
    EvidenceStatus,
    EvidenceType,
    LifecycleStatus,
    RecordOrigin,
    RequirementSourceType,
    RequirementStatus,
    Verdict,
)
from threatsight_api.persistence.models import (
    AISystemRecord,
    AssuranceRunRecord,
    AssuranceTargetRecord,
    ControlRecord,
    EvidenceControlLink,
    EvidenceRecord,
    EvidenceSystemLink,
    FindingRecord,
    RemediationRecord,
    RequirementControlLink,
    RequirementRecord,
)
from threatsight_api.services.audit import record_audit

DEMO_SYSTEM_NAME = "Order support demo"
DEMO_ENVIRONMENT = "lab"


class AssuranceEngineError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def get_adapter(settings: Settings) -> TargetAdapter:
    return build_adapter(settings.assurance_adapter, settings.demo_agent_url)


def bootstrap_demo(db: Session, settings: Settings, actor: str) -> dict:
    control = db.scalar(select(ControlRecord).where(ControlRecord.identifier == CTRL_002))
    if control is None:
        now = datetime.now(UTC)
        control = ControlRecord(
            identifier=CTRL_002,
            title="Tool authorization must be enforced outside the model",
            objective="Unauthorized cancel_order must be denied by a gateway, not by model narration.",
            description="AUTH-01 unauthorized cancellation; AUTH-02 authorized owner path.",
            owner="security",
            lifecycle=LifecycleStatus.ACTIVE.value,
            version=1,
            severity=ControlSeverity.HIGH.value,
            assurance_status=AssuranceStatus.EVIDENCE_REQUIRED.value,
            assurance_rationale="Awaiting CTRL-002 execution evidence.",
            assurance_set_by=actor,
            assurance_set_at=now,
        )
        db.add(control)
        db.flush()
        record_audit(
            db,
            entity_type="control",
            entity_id=control.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={"identifier": CTRL_002, "source": "m3-bootstrap"},
        )
    requirement = db.scalar(
        select(RequirementRecord).where(RequirementRecord.source_reference == "ctrl-002-bootstrap")
    )
    if requirement is None:
        requirement = RequirementRecord(
            title="High-impact tools require authorization outside the model",
            statement="Unauthorized cancellation of customer orders must be denied independently of the model.",
            source_type=RequirementSourceType.POLICY.value,
            source_reference="ctrl-002-bootstrap",
            version=1,
            status=RequirementStatus.APPROVED.value,
        )
        db.add(requirement)
        db.flush()
        link = RequirementControlLink(
            requirement_id=requirement.id,
            control_id=control.id,
            rationale="CTRL-002 is the first validated tool-authorization control.",
            provenance="m3-bootstrap",
        )
        db.add(link)
    system = db.scalar(
        select(AISystemRecord).where(
            AISystemRecord.name == DEMO_SYSTEM_NAME,
            AISystemRecord.environment == DEMO_ENVIRONMENT,
        )
    )
    if system is None:
        system = AISystemRecord(
            name=DEMO_SYSTEM_NAME,
            description="Synthetic order-support agent used only for CTRL-002 demonstration.",
            owner="platform",
            team="assurance",
            lifecycle=LifecycleStatus.ACTIVE.value,
            risk_classification="internal-demo",
            environment=DEMO_ENVIRONMENT,
            record_origin=RecordOrigin.SHOWCASE.value,
        )
        db.add(system)
        db.flush()
        record_audit(
            db,
            entity_type="ai_system",
            entity_id=system.id,
            action=AuditAction.CREATE,
            actor=actor,
            payload={"name": DEMO_SYSTEM_NAME, "environment": DEMO_ENVIRONMENT, "record_origin": RecordOrigin.SHOWCASE.value},
        )
    else:
        system.record_origin = RecordOrigin.SHOWCASE.value
    target = db.scalar(select(AssuranceTargetRecord).where(AssuranceTargetRecord.ai_system_id == system.id))
    expires = datetime.now(UTC) + timedelta(hours=24)
    if target is None:
        target = AssuranceTargetRecord(
            ai_system_id=system.id,
            adapter=settings.assurance_adapter,
            base_url=settings.demo_agent_url,
            agent_version="demo-order-support-1.0",
            authorized=True,
            authorization_expires_at=expires,
        )
        db.add(target)
        db.flush()
    else:
        target.adapter = settings.assurance_adapter
        target.base_url = settings.demo_agent_url
        target.authorized = True
        target.authorization_expires_at = expires
    db.flush()
    adapter = get_adapter(settings)
    adapter.reset("open")
    return {
        "system_id": str(system.id),
        "control_id": str(control.id),
        "target_id": str(target.id),
        "scenarios": [item.key for item in CATALOG.values()],
        "authorization_mode": adapter.state().get("authorization_mode"),
    }


def execute_run(
    db: Session,
    settings: Settings,
    *,
    scenario_key: str,
    actor: str,
    confirm_execution: bool,
    parent_run_id=None,
) -> AssuranceRunRecord:
    try:
        scenario = get_scenario(scenario_key)
    except ValueError as exc:
        raise AssuranceEngineError(str(exc), 400) from exc
    assert_execution_allowed(settings, confirm_execution=confirm_execution, target_url=settings.demo_agent_url)
    control = db.scalar(select(ControlRecord).where(ControlRecord.identifier == CTRL_002))
    system = db.scalar(
        select(AISystemRecord).where(
            AISystemRecord.name == DEMO_SYSTEM_NAME,
            AISystemRecord.environment == DEMO_ENVIRONMENT,
        )
    )
    target = (
        db.scalar(select(AssuranceTargetRecord).where(AssuranceTargetRecord.ai_system_id == system.id))
        if system
        else None
    )
    if control is None or system is None or target is None:
        raise AssuranceEngineError("CTRL-002 demo is not bootstrapped", 409)
    if not target.authorized:
        raise AssuranceSafetyError("Target authorization is not granted")
    if target.authorization_expires_at and target.authorization_expires_at < datetime.now(UTC):
        raise AssuranceSafetyError("Target authorization has expired")
    parent = None
    if parent_run_id is not None:
        parent = db.get(AssuranceRunRecord, parent_run_id)
        if parent is None:
            raise AssuranceEngineError("Parent run not found", 404)
    adapter = get_adapter(settings)
    adapter.reset()
    started = datetime.now(UTC)
    run = AssuranceRunRecord(
        id=uuid4(),
        control_id=control.id,
        ai_system_id=system.id,
        target_id=target.id,
        scenario_key=scenario.key,
        configuration={},
        verdict=Verdict.INCONCLUSIVE.value,
        reason_code="PENDING",
        parent_run_id=parent.id if parent else None,
        actor=actor,
        started_at=started,
    )
    db.add(run)
    db.flush()
    try:
        response = adapter.invoke(AdapterRequest(scenario=scenario, target_url=settings.demo_agent_url))
    except Exception as exc:
        run.verdict = Verdict.INCONCLUSIVE.value
        run.reason_code = "ADAPTER_FAILURE"
        run.finished_at = datetime.now(UTC)
        run.configuration = {"error": str(exc)[:500]}
        record_audit(
            db,
            entity_type="assurance_run",
            entity_id=run.id,
            action=AuditAction.EXECUTE,
            actor=actor,
            payload={"scenario": scenario.key, "verdict": run.verdict, "reason_code": run.reason_code},
        )
        db.flush()
        return run

    observation = response.observations[0] if response.observations else None
    decision = evaluate_ctrl002(scenario, observation)
    captured = datetime.now(UTC)
    envelope = canonical_envelope(
        run_id=run.id,
        control_id=control.id,
        control_identifier=control.identifier,
        ai_system_id=system.id,
        scenario_key=scenario.key,
        agent_version=response.agent_version,
        configuration=response.configuration,
        tool_name=observation.tool_name if observation else None,
        tool_arguments=observation.arguments if observation else None,
        authorization_decision=decision.authorization_decision,
        policy_decision=decision.reason_code,
        tool_result=observation.result if observation else None,
        completed_side_effect=observation.completed_side_effect if observation else None,
        evaluator=decision.evaluator,
        captured_at=captured,
    )
    digest = hash_envelope(envelope)
    evidence = EvidenceRecord(
        title=f"{control.identifier} {scenario.key} {decision.verdict.value}",
        description=decision.summary,
        evidence_type=EvidenceType.TEST_ARTIFACT.value,
        source_reference=f"run:{run.id}",
        provenance=f"sha256:{digest}",
        collected_at=captured,
        owner=actor,
        status=EvidenceStatus.ACCEPTED.value,
        document_ref=digest,
        envelope=envelope,
        integrity_hash=digest,
    )
    db.add(evidence)
    db.flush()
    db.add(EvidenceControlLink(evidence_id=evidence.id, control_id=control.id))
    db.add(EvidenceSystemLink(evidence_id=evidence.id, ai_system_id=system.id))
    run.configuration = response.configuration
    run.verdict = decision.verdict.value
    run.reason_code = decision.reason_code
    run.evidence_id = evidence.id
    run.finished_at = captured
    run.observation = observation.model_dump() if observation else {}
    run.narration = response.narration
    control.latest_verdict = decision.verdict.value
    control.version += 1
    now = datetime.now(UTC)
    if decision.verdict == Verdict.FAIL:
        control.assurance_status = AssuranceStatus.GAP_DETECTED.value
        control.assurance_rationale = decision.summary
        finding = FindingRecord(
            ai_system_id=system.id,
            control_id=control.id,
            run_id=run.id,
            evidence_id=evidence.id,
            severity=ControlSeverity.HIGH.value,
            title="Unauthorized cancel_order completed",
            status="open",
            verdict=decision.verdict.value,
            summary=decision.summary,
        )
        db.add(finding)
        db.flush()
        run.finding_id = finding.id
    elif decision.verdict == Verdict.PASS:
        control.assurance_status = (
            AssuranceStatus.VALIDATED.value if scenario.key == AUTH_01 else control.assurance_status
        )
        if scenario.key == AUTH_01:
            control.assurance_rationale = decision.summary
        if parent and parent.finding_id:
            finding = db.get(FindingRecord, parent.finding_id)
            if finding:
                finding.status = "resolved"
                finding.resolved_run_id = run.id
    else:
        control.assurance_status = AssuranceStatus.HUMAN_REVIEW_REQUIRED.value
        control.assurance_rationale = decision.summary
    control.assurance_set_by = actor
    control.assurance_set_at = now
    record_audit(
        db,
        entity_type="assurance_run",
        entity_id=run.id,
        action=AuditAction.EXECUTE if parent is None else AuditAction.RETEST,
        actor=actor,
        payload={
            "scenario": scenario.key,
            "verdict": run.verdict,
            "reason_code": run.reason_code,
            "evidence_hash": digest,
            "legal_compliance_claim": False,
        },
    )
    record_audit(
        db,
        entity_type="control",
        entity_id=control.id,
        action=AuditAction.STATUS_CHANGE,
        actor=actor,
        payload={"latest_verdict": control.latest_verdict, "assurance_status": control.assurance_status},
    )
    db.flush()
    return run


def remediate(db: Session, settings: Settings, finding_id, actor: str) -> RemediationRecord:
    finding = db.get(FindingRecord, finding_id)
    if finding is None:
        raise AssuranceEngineError("Finding not found", 404)
    if finding.status == "resolved":
        raise AssuranceEngineError("Finding is already resolved", 409)
    adapter = get_adapter(settings)
    adapter.configure("gateway")
    record = RemediationRecord(
        finding_id=finding.id,
        control_id=finding.control_id,
        action="enable_gateway_authorization",
        detail="Authorization gateway enabled on the synthetic demo agent. Not a legal conclusion.",
        actor=actor,
    )
    db.add(record)
    db.flush()
    finding.status = "remediated"
    record_audit(
        db,
        entity_type="finding",
        entity_id=finding.id,
        action=AuditAction.REMEDIATE,
        actor=actor,
        payload={"action": record.action, "authorization_mode": "gateway"},
    )
    return record
