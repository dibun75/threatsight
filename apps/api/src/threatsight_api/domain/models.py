from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

from threatsight_api.domain.enums import (
    ControlSeverity,
    LifecycleStatus,
    RequirementReviewStatus,
    Verdict,
)
from threatsight_api.domain.invariants import DETERMINISTIC_EVALUATOR, assert_verdict_evaluator

ASSURANCE_LOOP = (
    "requirement",
    "control",
    "test",
    "observe",
    "evidence",
    "verdict",
    "remediation",
    "retest",
    "assurance",
)


class AISystem(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    owner: str
    business_purpose: str
    environment: str
    model_provider: str | None = None
    lifecycle: LifecycleStatus = LifecycleStatus.DRAFT
    risk_classification: str | None = None


class Requirement(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    statement: str
    source_document: str | None = None
    source_locator: str | None = None
    extracted_text: str | None = None
    confidence: float | None = None
    review_status: RequirementReviewStatus = RequirementReviewStatus.CANDIDATE
    version: int = 1


class Control(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    identifier: str
    title: str
    expected_behavior: str
    owner: str
    severity: ControlSeverity
    requirement_ids: list[UUID] = Field(default_factory=list)
    test_ids: list[UUID] = Field(default_factory=list)
    framework_mappings: list[str] = Field(default_factory=list)
    applicability: str | None = None
    review_date: datetime | None = None
    latest_verdict: Verdict | None = None


class EvidenceEnvelope(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    control_id: UUID
    scenario: str | None = None
    tool_name: str | None = None
    authorization_decision: str | None = None
    policy_decision: str | None = None
    completed_side_effect: str | None = None
    captured_at: datetime
    evidence_hash: str | None = None


class VerdictRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    evidence_id: UUID
    verdict: Verdict
    evaluator: str = DETERMINISTIC_EVALUATOR
    reason_code: str
    recorded_at: datetime

    @field_validator("evaluator")
    @classmethod
    def evaluator_must_be_deterministic(cls, value: str) -> str:
        assert_verdict_evaluator(value)
        return value
