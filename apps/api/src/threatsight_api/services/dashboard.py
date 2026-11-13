from __future__ import annotations

from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatsight_api.assurance.engine import DEMO_ENVIRONMENT, DEMO_SYSTEM_NAME
from threatsight_api.domain.enums import AssuranceStatus, CandidateReviewStatus, RecordOrigin
from threatsight_api.frameworks.engine import coverage_totals
from threatsight_api.intelligence.llm import llm_configured
from threatsight_api.config import get_settings
from threatsight_api.persistence.models import (
    AISystemRecord,
    AssuranceRunRecord,
    ControlRecord,
    DiscoveredAsset,
    DiscoverySignal,
    DiscoverySource,
    EvidenceControlLink,
    EvidenceRecord,
    EvidenceSystemLink,
    ExtractionCandidate,
    FindingRecord,
    FrameworkReference,
    IntelTechnique,
    RequirementControlLink,
    RequirementRecord,
    RemediationRecord,
    SourceDocument,
)
from threatsight_api.services.freshness import freshness_totals
from threatsight_api.services.identity import identity_for
from threatsight_api.services.provenance import (
    controls_provenance,
    discovery_provenance,
    documents_provenance,
    evidence_provenance,
    findings_provenance,
    frameworks_provenance,
    freshness_provenance,
    iso_stamp,
    latest_stamp,
    systems_provenance,
    threats_provenance,
)
from threatsight_api.services.copy import humanize_action
from threatsight_api.services.operations import build_operations
from threatsight_api.services.summary import build_executive_summary
from threatsight_api.threats.engine import intel_totals

ASSURANCE_KEYS = [status.value for status in AssuranceStatus]
HIGH_SEVERITY = frozenset({"high", "critical"})


def count_enum(values: list[str], allowed: list[str]) -> dict[str, int]:
    tallies = Counter(values)
    return {key: int(tallies.get(key, 0)) for key in allowed}


def build_dashboard(db: Session, *, scope: str | None = None) -> dict:
    all_systems = list(db.scalars(select(AISystemRecord)))
    has_showcase = any(item.record_origin == RecordOrigin.SHOWCASE.value for item in all_systems)
    resolved = scope or ("showcase" if has_showcase else "all")
    if resolved not in {"showcase", "all"}:
        resolved = "all"
    if resolved == "showcase":
        systems = [item for item in all_systems if item.record_origin == RecordOrigin.SHOWCASE.value]
    else:
        systems = all_systems
    system_ids = {item.id for item in systems}
    all_findings = list(db.scalars(select(FindingRecord)))
    findings = [item for item in all_findings if resolved == "all" or item.ai_system_id in system_ids]
    all_runs = list(db.scalars(select(AssuranceRunRecord).order_by(AssuranceRunRecord.started_at.desc())))
    scoped_runs = [item for item in all_runs if resolved == "all" or item.ai_system_id in system_ids]
    runs = scoped_runs[:8]
    if resolved == "showcase":
        related_ids = set()
        for system in systems:
            related_ids |= related_control_ids(db, system.id)
        ctrl002 = db.scalar(select(ControlRecord).where(ControlRecord.identifier == "CTRL-002"))
        if ctrl002 is not None and system_ids:
            related_ids.add(ctrl002.id)
        controls = (
            list(db.scalars(select(ControlRecord).where(ControlRecord.id.in_(related_ids)))) if related_ids else []
        )
        evidence_ids = set()
        if system_ids:
            evidence_ids = set(
                db.scalars(select(EvidenceSystemLink.evidence_id).where(EvidenceSystemLink.ai_system_id.in_(system_ids)))
            )
        evidence_rows = (
            list(db.scalars(select(EvidenceRecord).where(EvidenceRecord.id.in_(evidence_ids)))) if evidence_ids else []
        )
        pending_candidates = 0
        document_rows = []
        requirement_rows = list(db.scalars(select(RequirementRecord)))
        candidate_rows = []
        include_document_queue = False
    else:
        controls = list(db.scalars(select(ControlRecord)))
        document_rows = list(db.scalars(select(SourceDocument)))
        requirement_rows = list(db.scalars(select(RequirementRecord)))
        candidate_rows = list(db.scalars(select(ExtractionCandidate)))
        pending_candidates = sum(
            1 for item in candidate_rows if item.review_status == CandidateReviewStatus.PENDING.value
        )
        evidence_rows = list(db.scalars(select(EvidenceRecord)))
        include_document_queue = True
    discovery_sources = db.scalar(select(func.count()).select_from(DiscoverySource)) or 0
    discovery_assets = db.scalar(select(func.count()).select_from(DiscoveredAsset)) or 0
    pending_signals = db.scalar(
        select(func.count())
        .select_from(DiscoverySignal)
        .where(DiscoverySignal.review_status == CandidateReviewStatus.PENDING.value)
    ) or 0
    discovery_updated = db.scalar(select(func.max(DiscoverySource.updated_at)))
    framework_updated = db.scalar(select(func.max(FrameworkReference.updated_at)))
    threat_updated = db.scalar(select(func.max(IntelTechnique.updated_at)))
    synthetic = any(item.name == DEMO_SYSTEM_NAME and item.environment == DEMO_ENVIRONMENT for item in systems)
    open_findings = [item for item in findings if item.status == "open"]
    high_risk = [
        item
        for item in open_findings
        if item.severity in HIGH_SEVERITY
    ]
    high_risk.sort(key=lambda item: item.created_at, reverse=True)
    collapsed_high = collapse_findings(high_risk)
    systems_block = {"count": len(systems), "provenance": systems_provenance(systems)}
    controls_block = {
        "count": len(controls),
        "by_assurance_status": count_enum([item.assurance_status for item in controls], ASSURANCE_KEYS),
        "with_technical_verdict": sum(1 for item in controls if item.latest_verdict),
        "without_technical_verdict": sum(1 for item in controls if not item.latest_verdict),
        "provenance": controls_provenance(controls),
    }
    findings_block = {
        "count": len(findings),
        "open": len(open_findings),
        "high_or_critical_open": len(high_risk),
        "by_status": count_enum([item.status for item in findings], ["open", "remediated", "resolved"]),
        "by_severity": count_enum([item.severity for item in findings], ["critical", "high", "medium", "low"]),
        "provenance": findings_provenance(findings),
    }
    documents_block = {
        "count": len(document_rows),
        "pending_candidates": int(pending_candidates),
        "requirements": len(requirement_rows),
        "provenance": documents_provenance(document_rows, requirement_rows, candidate_rows),
    }
    discovery_block = {
        "sources": int(discovery_sources),
        "assets": int(discovery_assets),
        "pending_signals": int(pending_signals),
        "provenance": discovery_provenance(
            source_count=int(discovery_sources),
            last_updated=iso_stamp(discovery_updated),
        ),
    }
    frameworks_block = coverage_totals(db)
    frameworks_block["provenance"] = frameworks_provenance(
        item_count=int(frameworks_block.get("item_count", 0)),
        last_updated=iso_stamp(framework_updated),
    )
    threats_block = intel_totals(db)
    threats_block["provenance"] = threats_provenance(
        technique_count=int(threats_block.get("technique_count", 0)),
        last_updated=iso_stamp(threat_updated),
    )
    freshness_block = freshness_totals(db, controls=controls, evidence_rows=evidence_rows)
    freshness_block["provenance"] = freshness_provenance(
        last_updated=latest_stamp(evidence_rows, "updated_at", "collected_at", "created_at"),
    )
    settings = get_settings()
    payload = {
        "legal_compliance_claim": False,
        "synthetic_demo_labelled": True,
        "synthetic_demo_present": synthetic,
        "scope": resolved,
        "scope_reason": "showcase_origin_present" if resolved == "showcase" else "all_records",
        "systems": systems_block,
        "controls": controls_block,
        "findings": findings_block,
        "evidence": {"count": len(evidence_rows), "provenance": evidence_provenance(evidence_rows)},
        "documents": documents_block,
        "discovery": discovery_block,
        "frameworks": frameworks_block,
        "threats": threats_block,
        "high_risk_findings": [item for item, _count in collapsed_high[:8]],
        "high_risk_duplicate_counts": [count for _item, count in collapsed_high[:8]],
        "recent_runs": runs,
        "recent_activity": recent_activity(db, findings=findings, runs=scoped_runs),
        "evidence_freshness": freshness_block,
        "llm_available": llm_configured(settings),
        "intelligence_provider": (settings.intelligence_provider or "heuristic").strip().lower(),
        "operations": build_operations(
            db,
            systems=systems,
            controls=controls,
            findings=findings,
            runs=scoped_runs[:8],
            freshness=freshness_block,
            pending_docs=pending_candidates,
            include_document_queue=include_document_queue,
        ),
    }
    payload["executive_summary"] = build_executive_summary(payload)
    return payload


def collapse_findings(findings: list) -> list[tuple]:
    grouped: dict[tuple, list] = {}
    for item in findings:
        key = (item.ai_system_id, item.control_id, item.title, item.status, item.verdict)
        grouped.setdefault(key, []).append(item)
    collapsed = []
    for rows in grouped.values():
        rows.sort(key=lambda item: item.created_at, reverse=True)
        collapsed.append((rows[0], len(rows)))
    collapsed.sort(key=lambda pair: pair[0].created_at, reverse=True)
    return collapsed


def recent_activity(db: Session, *, findings, runs, limit: int = 10) -> list[dict]:
    events: list[dict] = []
    for item in runs[:limit]:
        events.append(
            {
                "kind": "retest" if item.parent_run_id else "test",
                "title": f"{item.scenario_key} {item.verdict}",
                "href": f"/findings/{item.finding_id}" if item.finding_id else "/assurance",
                "at": item.finished_at.isoformat() if item.finished_at else item.started_at.isoformat(),
                "verdict": item.verdict,
            }
        )
    for item in findings[:limit]:
        events.append(
            {
                "kind": "finding",
                "title": item.title,
                "href": f"/findings/{item.id}",
                "at": item.created_at.isoformat() if item.created_at else None,
                "verdict": item.verdict,
            }
        )
    finding_ids = [item.id for item in findings]
    if finding_ids:
        for item in db.scalars(
            select(RemediationRecord)
            .where(RemediationRecord.finding_id.in_(finding_ids))
            .order_by(RemediationRecord.created_at.desc())
            .limit(limit)
        ):
            events.append(
                {
                    "kind": "remediation",
                    "title": humanize_action(item.action),
                    "href": f"/findings/{item.finding_id}",
                    "at": item.created_at.isoformat() if item.created_at else None,
                    "verdict": None,
                }
            )
    events = [item for item in events if item.get("at")]
    events.sort(key=lambda item: item["at"] or "", reverse=True)
    return events[:limit]


def posture_summary(*, findings, runs, missing, controls) -> str:
    high_open = any(item.status == "open" and item.severity in HIGH_SEVERITY for item in findings)
    pending_retest = any(item.status == "remediated" for item in findings)
    latest = runs[0].verdict if runs else None
    review = any(item.assurance_status == "HUMAN_REVIEW_REQUIRED" for item in controls) or bool(missing)
    if high_open:
        return "ATTENTION REQUIRED"
    if pending_retest:
        return "ATTENTION REQUIRED"
    if latest == "FAIL":
        return "ATTENTION REQUIRED"
    if not latest:
        return "NOT ASSESSED"
    if latest == "PASS" and not high_open:
        if review:
            return "REVIEW REQUIRED"
        return "NO TESTED GAPS"
    return "REVIEW REQUIRED"


def related_control_ids(db: Session, system_id) -> set:
    ids: set = set()
    for finding in db.scalars(select(FindingRecord).where(FindingRecord.ai_system_id == system_id)):
        ids.add(finding.control_id)
    evidence_ids = list(
        db.scalars(select(EvidenceSystemLink.evidence_id).where(EvidenceSystemLink.ai_system_id == system_id))
    )
    if evidence_ids:
        for control_id in db.scalars(
            select(EvidenceControlLink.control_id).where(EvidenceControlLink.evidence_id.in_(evidence_ids))
        ):
            ids.add(control_id)
    for control_id in db.scalars(
        select(AssuranceRunRecord.control_id).where(AssuranceRunRecord.ai_system_id == system_id)
    ):
        ids.add(control_id)
    return ids


def load_system_graph(db: Session, system: AISystemRecord) -> dict:
    control_ids = related_control_ids(db, system.id)
    controls = (
        list(db.scalars(select(ControlRecord).where(ControlRecord.id.in_(control_ids)).order_by(ControlRecord.identifier)))
        if control_ids
        else []
    )
    findings = list(
        db.scalars(
            select(FindingRecord)
            .where(FindingRecord.ai_system_id == system.id)
            .order_by(FindingRecord.created_at.desc())
        )
    )
    evidence_ids = list(
        db.scalars(select(EvidenceSystemLink.evidence_id).where(EvidenceSystemLink.ai_system_id == system.id))
    )
    evidence = (
        list(db.scalars(select(EvidenceRecord).where(EvidenceRecord.id.in_(evidence_ids)).order_by(EvidenceRecord.created_at.desc())))
        if evidence_ids
        else []
    )
    requirement_ids = set()
    if control_ids:
        for requirement_id in db.scalars(
            select(RequirementControlLink.requirement_id).where(RequirementControlLink.control_id.in_(control_ids))
        ):
            requirement_ids.add(requirement_id)
    requirements = (
        list(db.scalars(select(RequirementRecord).where(RequirementRecord.id.in_(requirement_ids)).order_by(RequirementRecord.title)))
        if requirement_ids
        else []
    )
    return {
        "controls": controls,
        "findings": findings,
        "evidence": evidence,
        "requirements": requirements,
    }


def load_system_ops(db: Session, system: AISystemRecord, graph: dict) -> dict:
    from threatsight_api.connectivity.ingest import event_to_dict
    from threatsight_api.persistence.models import (
        AgentEvent,
        AISystemProfile,
        AssuranceRunRecord,
        IntelTechnique,
        IntelTechniqueControl,
        IntelThreat,
    )

    profile = db.scalar(select(AISystemProfile).where(AISystemProfile.ai_system_id == system.id))
    events = list(
        db.scalars(
            select(AgentEvent)
            .where(AgentEvent.ai_system_id == system.id)
            .order_by(AgentEvent.occurred_at.desc())
            .limit(20)
        )
    )
    runs = list(
        db.scalars(
            select(AssuranceRunRecord)
            .where(AssuranceRunRecord.ai_system_id == system.id)
            .order_by(AssuranceRunRecord.started_at.desc())
            .limit(8)
        )
    )
    missing = []
    purpose = profile.purpose if profile and profile.purpose else system.description
    data_categories = list(profile.data_categories) if profile else []
    users_subjects = list(profile.users_subjects) if profile else []
    capabilities = list(profile.capabilities) if profile else []
    if not purpose:
        missing.append("purpose")
    if not data_categories:
        missing.append("data_categories")
    if not users_subjects:
        missing.append("users_subjects")
    if not capabilities:
        missing.append("capabilities")
    if not graph["controls"]:
        missing.append("controls")
    if not graph["requirements"]:
        missing.append("requirements")
    if not graph["evidence"]:
        missing.append("evidence")
    if not runs:
        missing.append("assurance_tests")
    if profile and profile.missing:
        missing.extend(str(item) for item in profile.missing)
    unique_missing = list(dict.fromkeys(missing))
    control_ids = [item.id for item in graph["controls"]]
    exposure = []
    if control_ids:
        for link in db.scalars(
            select(IntelTechniqueControl).where(IntelTechniqueControl.control_id.in_(control_ids))
        ):
            technique = db.get(IntelTechnique, link.technique_id)
            if technique is None:
                continue
            threat = db.get(IntelThreat, technique.threat_id)
            exposure.append(
                {
                    "threat_key": threat.key if threat else None,
                    "threat_title": threat.title if threat else None,
                    "technique_key": technique.key,
                    "technique_title": technique.title,
                    "affected_capability": technique.affected_capability,
                    "control_id": str(link.control_id),
                    "informational_only": True,
                    "href": f"/threats/{threat.key if threat else ''}/{technique.key}",
                }
            )
    findings = graph["findings"]
    remediation = {
        "open": sum(1 for item in findings if item.status == "open"),
        "remediated": sum(1 for item in findings if item.status == "remediated"),
        "resolved": sum(1 for item in findings if item.status == "resolved"),
        "latest_verdict": runs[0].verdict if runs else "UNKNOWN",
    }
    tests = [
        {
            "id": str(item.id),
            "scenario_key": item.scenario_key,
            "verdict": item.verdict,
            "reason_code": item.reason_code,
            "parent_run_id": str(item.parent_run_id) if item.parent_run_id else None,
            "finished_at": item.finished_at.isoformat() if item.finished_at else None,
        }
        for item in runs
    ]
    ident = identity_for(system)
    return {
        "profile": {
            "purpose": purpose or "UNKNOWN",
            "labelled_synthetic": bool(profile.labelled_synthetic) if profile else ident["labelled_synthetic"],
            "legal_compliance_claim": False,
        }
        if profile or purpose
        else None,
        "identity": ident,
        "posture_summary": posture_summary(
            findings=graph["findings"],
            runs=runs,
            missing=unique_missing,
            controls=graph["controls"],
        ),
        "capabilities": capabilities,
        "data_categories": data_categories,
        "users_subjects": users_subjects,
        "traces": [event_to_dict(item) for item in events],
        "threat_exposure": exposure,
        "missing_information": unique_missing,
        "tests": tests,
        "remediation_state": remediation,
    }


def findings_to_out(db: Session, rows) -> list:
    from threatsight_api.api.schemas import FindingOut

    if not rows:
        return []
    system_ids = {item.ai_system_id for item in rows}
    control_ids = {item.control_id for item in rows}
    systems = {
        item.id: item
        for item in db.scalars(select(AISystemRecord).where(AISystemRecord.id.in_(system_ids)))
    }
    controls = {
        item.id: item.identifier
        for item in db.scalars(select(ControlRecord).where(ControlRecord.id.in_(control_ids)))
    }
    return [
        FindingOut(
            id=item.id,
            ai_system_id=item.ai_system_id,
            control_id=item.control_id,
            run_id=item.run_id,
            evidence_id=item.evidence_id,
            resolved_run_id=item.resolved_run_id,
            severity=item.severity,
            title=item.title,
            status=item.status,
            verdict=item.verdict,
            summary=item.summary,
            created_at=item.created_at,
            updated_at=item.updated_at,
            ai_system_name=systems[item.ai_system_id].name if item.ai_system_id in systems else None,
            ai_system_display_name=(
                identity_for(systems[item.ai_system_id])["display_name"] if item.ai_system_id in systems else None
            ),
            control_identifier=controls.get(item.control_id),
        )
        for item in rows
    ]
