from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from threatsight_api.domain.assurance import assert_assurance_status
from threatsight_api.domain.enums import (
    AssuranceStatus,
    CandidateReviewStatus,
    ControlSeverity,
    EvidenceStatus,
    EvidenceType,
    FrameworkKey,
    LifecycleStatus,
    MappingProposalAction,
    RequirementSourceType,
    RequirementStatus,
    ReviewDecision,
    ReviewableEntity,
)

TITLE = Field(min_length=1, max_length=200)
OWNER = Field(min_length=1, max_length=200)
TEXT = Field(min_length=1, max_length=20000)
OPT_TEXT = Field(default=None, max_length=20000)
REF = Field(default=None, max_length=500)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AISystemCreate(StrictModel):
    name: str = TITLE
    description: str | None = OPT_TEXT
    owner: str = OWNER
    team: str | None = Field(default=None, max_length=200)
    lifecycle: LifecycleStatus = LifecycleStatus.DRAFT
    risk_classification: str | None = Field(default=None, max_length=64)
    environment: str = Field(min_length=1, max_length=64)


class AISystemUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = OPT_TEXT
    owner: str | None = Field(default=None, min_length=1, max_length=200)
    team: str | None = Field(default=None, max_length=200)
    lifecycle: LifecycleStatus | None = None
    risk_classification: str | None = Field(default=None, max_length=64)
    environment: str | None = Field(default=None, min_length=1, max_length=64)


class AISystemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    owner: str
    team: str | None
    lifecycle: str
    risk_classification: str | None
    environment: str
    record_origin: str = "manual"
    created_at: datetime
    updated_at: datetime

    @computed_field
    @property
    def display_name(self) -> str:
        from threatsight_api.services.identity import display_name_for

        return display_name_for(self.name, self.environment)

    @computed_field
    @property
    def organisation(self) -> str | None:
        from threatsight_api.services.identity import organisation_for

        return organisation_for(self.name, self.environment)

    @computed_field
    @property
    def technical_identifier(self) -> str:
        return self.name

    @computed_field
    @property
    def labelled_synthetic(self) -> bool:
        from threatsight_api.services.identity import is_labelled_showcase

        return is_labelled_showcase(self.name, self.environment)

    @computed_field
    @property
    def origin_label(self) -> str:
        from threatsight_api.services.identity import ORIGIN_LABELS

        return ORIGIN_LABELS.get(self.record_origin, self.record_origin)

    @computed_field
    @property
    def supporting_inventory(self) -> bool:
        from threatsight_api.services.identity import is_knowledge_demo

        return is_knowledge_demo(self.name, self.environment)


class RequirementCreate(StrictModel):
    title: str = TITLE
    statement: str = TEXT
    source_type: RequirementSourceType = RequirementSourceType.MANUAL
    source_reference: str | None = REF
    status: RequirementStatus = RequirementStatus.CANDIDATE


class RequirementUpdate(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    statement: str | None = Field(default=None, min_length=1, max_length=20000)
    source_type: RequirementSourceType | None = None
    source_reference: str | None = REF
    status: RequirementStatus | None = None


class RequirementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    statement: str
    source_type: str
    source_reference: str | None
    version: int
    status: str
    created_at: datetime
    updated_at: datetime


class ControlCreate(StrictModel):
    identifier: str = Field(min_length=3, max_length=32, pattern=r"^[A-Z][A-Z0-9_-]{1,31}$")
    title: str = TITLE
    objective: str = TEXT
    description: str | None = OPT_TEXT
    owner: str = OWNER
    lifecycle: LifecycleStatus = LifecycleStatus.DRAFT
    severity: ControlSeverity | None = None
    assurance_status: AssuranceStatus = AssuranceStatus.EVIDENCE_REQUIRED
    assurance_rationale: str | None = OPT_TEXT

    @field_validator("assurance_status", mode="before")
    @classmethod
    def validate_assurance(cls, value: str) -> str:
        return assert_assurance_status(str(value)).value


class ControlUpdate(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    objective: str | None = Field(default=None, min_length=1, max_length=20000)
    description: str | None = OPT_TEXT
    owner: str | None = Field(default=None, min_length=1, max_length=200)
    lifecycle: LifecycleStatus | None = None
    severity: ControlSeverity | None = None
    assurance_status: AssuranceStatus | None = None
    assurance_rationale: str | None = OPT_TEXT

    @field_validator("assurance_status", mode="before")
    @classmethod
    def validate_assurance(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return assert_assurance_status(str(value)).value


class ControlOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    identifier: str
    title: str
    objective: str
    description: str | None
    owner: str
    lifecycle: str
    version: int
    severity: str | None
    assurance_status: str
    assurance_rationale: str | None
    assurance_set_by: str | None
    assurance_set_at: datetime | None
    latest_verdict: str | None = None
    created_at: datetime
    updated_at: datetime


class MappingCreate(StrictModel):
    requirement_id: uuid.UUID
    rationale: str | None = OPT_TEXT
    provenance: str | None = REF


class MappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    requirement_id: uuid.UUID
    control_id: uuid.UUID
    rationale: str | None
    provenance: str | None
    created_at: datetime


class EvidenceCreate(StrictModel):
    title: str = TITLE
    description: str | None = OPT_TEXT
    evidence_type: EvidenceType = EvidenceType.MANUAL
    source_reference: str | None = REF
    provenance: str | None = OPT_TEXT
    collected_at: datetime | None = None
    owner: str = OWNER
    status: EvidenceStatus = EvidenceStatus.DRAFT
    document_ref: str | None = REF
    control_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    ai_system_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)


class EvidenceUpdate(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = OPT_TEXT
    evidence_type: EvidenceType | None = None
    source_reference: str | None = REF
    provenance: str | None = OPT_TEXT
    collected_at: datetime | None = None
    owner: str | None = Field(default=None, min_length=1, max_length=200)
    status: EvidenceStatus | None = None
    document_ref: str | None = REF


class EvidenceOut(BaseModel):
    id: uuid.UUID
    title: str
    description: str | None
    evidence_type: str
    source_reference: str | None
    provenance: str | None
    collected_at: datetime | None
    owner: str
    status: str
    document_ref: str | None
    integrity_hash: str | None = None
    envelope: dict | None = None
    control_ids: list[uuid.UUID]
    ai_system_ids: list[uuid.UUID]
    created_at: datetime
    updated_at: datetime
    freshness: str | None = None
    freshness_window_days: int | None = None
    freshness_observed_at: datetime | None = None
    control_labels: list[str] = Field(default_factory=list)
    system_labels: list[str] = Field(default_factory=list)


class FrameworkReferenceCreate(StrictModel):
    framework_key: FrameworkKey
    reference_code: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=300)
    locator: str | None = REF


class FrameworkReferenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    framework_key: str
    reference_code: str
    title: str
    locator: str | None
    statement: str | None = None
    source_kind: str | None = None
    catalog_version: str | None = None
    informational_only: bool = True
    legal_compliance_claim: bool = False
    created_at: datetime
    updated_at: datetime


class FrameworkMapCreate(StrictModel):
    framework_reference_id: uuid.UUID
    note: str | None = OPT_TEXT


class FrameworkMapOut(BaseModel):
    id: uuid.UUID
    control_id: uuid.UUID
    framework_reference_id: uuid.UUID
    framework_key: str
    reference_code: str
    title: str
    locator: str | None = None
    note: str | None
    informational_only: bool = True
    legal_compliance_claim: bool = False


class ReviewCreate(StrictModel):
    entity_type: ReviewableEntity
    entity_id: uuid.UUID
    reviewer: str = OWNER
    decision: ReviewDecision
    comment: str | None = OPT_TEXT


class ReviewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    entity_type: str
    entity_id: uuid.UUID
    reviewer: str
    decision: str
    comment: str | None
    created_at: datetime


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    entity_type: str
    entity_id: uuid.UUID
    action: str
    actor: str
    at: datetime
    payload: dict


class DocumentOut(BaseModel):
    id: uuid.UUID
    title: str
    status: str
    current_version: int
    failure_reason: str | None
    uploaded_by: str
    latest_hash: str | None
    latest_media_kind: str | None
    candidate_count: int
    created_at: datetime
    updated_at: datetime


class DocumentVersionOut(BaseModel):
    id: uuid.UUID
    document_id: uuid.UUID
    version_number: int
    original_filename: str
    media_kind: str
    content_type: str
    byte_size: int
    content_hash: str
    page_count: int | None
    extraction_status: str
    extraction_provider: str | None
    extraction_model: str | None
    extracted_at: datetime | None
    extraction_warnings: list[str]
    extraction_error: str | None
    uploaded_by: str
    created_at: datetime


class DocumentVersionDetail(DocumentVersionOut):
    extracted_text: str
    locations: list[dict]


class CandidateProvenance(BaseModel):
    document_id: uuid.UUID
    document_title: str
    document_version_id: uuid.UUID
    version_number: int
    content_hash: str
    page: int | None
    section: str | None
    start_char: int | None
    end_char: int | None
    quote: str
    extracted_at: datetime
    extraction_method: str
    extraction_model: str


class CandidateOut(BaseModel):
    id: uuid.UUID
    document_id: uuid.UUID
    document_version_id: uuid.UUID
    version_number: int
    candidate_type: str
    review_status: str
    title: str
    statement: str
    confidence: float
    provenance: CandidateProvenance
    reviewer: str | None
    review_comment: str | None
    reviewed_at: datetime | None
    authoritative_requirement_id: uuid.UUID | None
    authoritative_control_id: uuid.UUID | None
    authoritative_evidence_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class CandidateUpdate(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    statement: str | None = Field(default=None, min_length=1, max_length=20000)


class CandidateReviewIn(StrictModel):
    decision: CandidateReviewStatus
    comment: str | None = OPT_TEXT
    title: str | None = Field(default=None, min_length=1, max_length=200)
    statement: str | None = Field(default=None, min_length=1, max_length=20000)

    @field_validator("decision")
    @classmethod
    def decision_must_change_state(cls, value: CandidateReviewStatus) -> CandidateReviewStatus:
        if value == CandidateReviewStatus.PENDING:
            raise ValueError("Review decision cannot be pending")
        return value


class ProposedControlIn(StrictModel):
    identifier: str | None = Field(default=None, min_length=3, max_length=32, pattern=r"^[A-Z][A-Z0-9_-]{1,31}$")
    title: str = TITLE
    objective: str = TEXT
    description: str | None = OPT_TEXT
    owner: str = OWNER
    severity: ControlSeverity | None = None


class CandidateMapIn(StrictModel):
    action: MappingProposalAction
    control_id: uuid.UUID | None = None
    new_control: ProposedControlIn | None = None
    rationale: str | None = OPT_TEXT


class CandidateMappingOut(BaseModel):
    id: uuid.UUID
    candidate_id: uuid.UUID
    action: str
    control_id: uuid.UUID | None
    requirement_id: uuid.UUID | None
    mapping_link_id: uuid.UUID | None
    rationale: str | None
    reviewer: str
    provenance: str
    created_at: datetime


class DocumentDetail(DocumentOut):
    versions: list[DocumentVersionOut]
    candidates: list[CandidateOut]


class AssuranceView(BaseModel):
    control_id: uuid.UUID
    identifier: str
    title: str
    assurance_status: str
    assurance_rationale: str | None
    provenance: str = "manual"
    legal_compliance_claim: bool = False
    requirements: list[RequirementOut]
    evidence: list[EvidenceOut]
    framework_mappings: list[FrameworkMapOut]
    reviews: list[ReviewOut]
    latest_technical_verdict: str | None = None
    freshness: str | None = None
    freshness_observed_at: datetime | None = None
    freshness_window_days: int | None = None


class RunCreate(StrictModel):
    scenario_key: str = Field(min_length=3, max_length=32)
    confirm_execution: bool = False
    parent_run_id: uuid.UUID | None = None


class RunOut(BaseModel):
    id: uuid.UUID
    control_id: uuid.UUID
    ai_system_id: uuid.UUID
    scenario_key: str
    configuration: dict
    observation: dict
    narration: str | None
    verdict: str
    reason_code: str
    evidence_id: uuid.UUID | None
    finding_id: uuid.UUID | None
    parent_run_id: uuid.UUID | None
    actor: str
    started_at: datetime
    finished_at: datetime | None
    legal_compliance_claim: bool = False
    evaluator: str = "deterministic_policy"


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ai_system_id: uuid.UUID
    control_id: uuid.UUID
    run_id: uuid.UUID
    evidence_id: uuid.UUID | None
    resolved_run_id: uuid.UUID | None
    severity: str
    title: str
    status: str
    verdict: str
    summary: str
    created_at: datetime
    updated_at: datetime
    ai_system_name: str | None = None
    ai_system_display_name: str | None = None
    control_identifier: str | None = None


class DashboardFinding(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    status: str
    verdict: str
    ai_system_id: uuid.UUID
    control_id: uuid.UUID
    evidence_id: uuid.UUID | None
    ai_system_name: str | None = None
    ai_system_display_name: str | None = None
    control_identifier: str | None = None
    duplicate_count: int = 1


class DashboardRun(BaseModel):
    id: uuid.UUID
    scenario_key: str
    verdict: str
    reason_code: str
    control_id: uuid.UUID
    finding_id: uuid.UUID | None
    evidence_id: uuid.UUID | None
    parent_run_id: uuid.UUID | None
    finished_at: datetime | None


class DashboardOut(BaseModel):
    legal_compliance_claim: bool = False
    synthetic_demo_labelled: bool = True
    synthetic_demo_present: bool
    scope: str = "all"
    scope_reason: str = "all_records"
    llm_available: bool = False
    intelligence_provider: str = "heuristic"
    systems: dict
    controls: dict
    findings: dict
    evidence: dict
    documents: dict
    discovery: dict
    frameworks: dict
    threats: dict
    high_risk_findings: list[DashboardFinding]
    recent_runs: list[DashboardRun]
    recent_activity: list[dict] = Field(default_factory=list)
    evidence_freshness: dict
    executive_summary: dict
    operations: dict = Field(default_factory=dict)


class IntelligenceExplainIn(StrictModel):
    system_id: uuid.UUID
    persist: bool = True
    use_llm: bool = False


class IntelligenceTaskIn(StrictModel):
    task: str = Field(min_length=1, max_length=64)
    system_id: uuid.UUID | None = None
    persist: bool = True
    use_llm: bool = False


class ShowcaseBootstrapIn(StrictModel):
    confirm_execution: bool = False


class ShowcaseResetIn(StrictModel):
    reseed: bool = True
    confirm_execution: bool = False


class SystemPostureOut(BaseModel):
    legal_compliance_claim: bool = False
    system: AISystemOut
    controls: list[ControlOut]
    findings: list[FindingOut]
    evidence: list[EvidenceOut]
    requirements: list[RequirementOut]
    profile: dict | None = None
    capabilities: list = Field(default_factory=list)
    data_categories: list = Field(default_factory=list)
    users_subjects: list = Field(default_factory=list)
    traces: list = Field(default_factory=list)
    threat_exposure: list = Field(default_factory=list)
    missing_information: list = Field(default_factory=list)
    tests: list = Field(default_factory=list)
    remediation_state: dict = Field(default_factory=dict)
    posture_summary: str = "NOT ASSESSED"
    identity: dict = Field(default_factory=dict)


class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    control_id: uuid.UUID
    action: str
    detail: str
    actor: str
    created_at: datetime


class DiscoverySourceCreate(StrictModel):
    url: str = Field(min_length=8, max_length=500)
    title: str | None = Field(default=None, min_length=1, max_length=200)
    owner: str = OWNER
    refresh_authorization: bool = False


class ScanCreate(StrictModel):
    confirm_execution: bool = False


class SignalReviewIn(StrictModel):
    decision: CandidateReviewStatus
    comment: str | None = OPT_TEXT

    @field_validator("decision")
    @classmethod
    def decision_must_change_state(cls, value: CandidateReviewStatus) -> CandidateReviewStatus:
        if value == CandidateReviewStatus.PENDING:
            raise ValueError("Review decision cannot be pending")
        return value


class SignalMapIn(StrictModel):
    control_id: uuid.UUID


class DiscoverySourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    title: str
    owner: str
    authorized: bool
    authorization_expires_at: datetime | None
    status: str
    last_scan_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class DiscoveryScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    status: str
    confirm_execution: bool
    robots_checked: bool
    pages_fetched: int
    content_hash: str | None
    error: str | None
    actor: str
    started_at: datetime
    finished_at: datetime | None


class DiscoveredAssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    scan_id: uuid.UUID
    kind: str
    title: str
    url: str
    summary: str | None
    status: str
    created_at: datetime
    updated_at: datetime
    pending_signals: int = 0


class DiscoverySignalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    scan_id: uuid.UUID
    asset_id: uuid.UUID
    signal_kind: str
    title: str
    statement: str
    quote: str
    page_url: str
    content_hash: str
    review_status: str
    reviewer: str | None
    review_comment: str | None
    reviewed_at: datetime | None
    evidence_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class DiscoveredAssetDetail(DiscoveredAssetOut):
    signals: list[DiscoverySignalOut]

