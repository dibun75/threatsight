from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threatsight_api.domain.assurance import FORBIDDEN_ASSURANCE_LABELS

INTELLIGENCE_TASKS = (
    "classify_system",
    "suggest_mappings",
    "correlate_threats",
    "missing_governance",
    "explain_posture",
)
IntelligenceTask = Literal[
    "classify_system",
    "suggest_mappings",
    "correlate_threats",
    "missing_governance",
    "explain_posture",
]
PROMPT_VERSION = "m13-v1"
TASK_VERSIONS = {task: f"m13-{task}-v1" for task in INTELLIGENCE_TASKS}


class StrictIntel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MappingSuggestion(StrictIntel):
    requirement_title: str = Field(min_length=1, max_length=200)
    control_identifier: str = Field(min_length=1, max_length=32)
    rationale: str = Field(min_length=1, max_length=2000)
    informational_only: bool = True


class ThreatCorrelation(StrictIntel):
    threat_key: str = Field(min_length=1, max_length=64)
    technique_key: str = Field(min_length=1, max_length=64)
    control_identifier: str | None = Field(default=None, max_length=32)
    affected_capability: str = Field(min_length=1, max_length=64)
    informational_only: bool = True


class ExplainStatement(StrictIntel):
    text: str = Field(min_length=1, max_length=2000)
    fact_id: str = Field(min_length=1, max_length=128)

    @field_validator("text")
    @classmethod
    def reject_compliance_label(cls, value: str) -> str:
        compact = value.strip()
        if compact.upper() in FORBIDDEN_ASSURANCE_LABELS or "COMPLIANT" in compact.upper():
            raise ValueError("Intelligence must not emit a legal-compliance label")
        return compact


class ClassifySystemOut(StrictIntel):
    purpose: str = Field(min_length=1, max_length=2000)
    data_categories: list[str] = Field(default_factory=list, max_length=50)
    users_subjects: list[str] = Field(default_factory=list, max_length=50)
    capabilities: list[str] = Field(default_factory=list, max_length=50)
    missing: list[str] = Field(default_factory=list, max_length=50)
    confidence: float = Field(ge=0, le=1)
    uncertainty: str = Field(min_length=1, max_length=2000)
    legal_compliance_claim: bool = False


class SuggestMappingsOut(StrictIntel):
    suggestions: list[MappingSuggestion] = Field(default_factory=list, max_length=50)
    missing: list[str] = Field(default_factory=list, max_length=50)
    confidence: float = Field(ge=0, le=1)
    uncertainty: str = Field(min_length=1, max_length=2000)
    informational_only: bool = True
    legal_compliance_claim: bool = False


class CorrelateThreatsOut(StrictIntel):
    correlations: list[ThreatCorrelation] = Field(default_factory=list, max_length=50)
    missing: list[str] = Field(default_factory=list, max_length=50)
    confidence: float = Field(ge=0, le=1)
    uncertainty: str = Field(min_length=1, max_length=2000)
    informational_only: bool = True
    legal_compliance_claim: bool = False


class MissingGovernanceOut(StrictIntel):
    missing: list[str] = Field(default_factory=list, max_length=50)
    confidence: float = Field(ge=0, le=1)
    uncertainty: str = Field(min_length=1, max_length=2000)
    never_invents: bool = True
    legal_compliance_claim: bool = False


class ExplainLlmOut(StrictIntel):
    statements: list[ExplainStatement] = Field(default_factory=list, max_length=40)
    recommended_action: str | None = Field(default=None, max_length=2000)
    missing: list[str] = Field(default_factory=list, max_length=50)
    confidence: float = Field(ge=0, le=1)
    uncertainty: str = Field(min_length=1, max_length=2000)
    legal_compliance_claim: bool = False


TASK_MODELS = {
    "classify_system": ClassifySystemOut,
    "suggest_mappings": SuggestMappingsOut,
    "correlate_threats": CorrelateThreatsOut,
    "missing_governance": MissingGovernanceOut,
    "explain_posture": ExplainLlmOut,
}


def validate_task_payload(task: str, payload: object):
    model = TASK_MODELS.get(task)
    if model is None:
        raise ValueError(f"Unknown intelligence task: {task}")
    if not isinstance(payload, dict):
        raise ValueError("Intelligence payload must be an object")
    allowed = set(model.model_fields)
    cleaned = {key: payload[key] for key in allowed if key in payload}
    cleaned.setdefault("legal_compliance_claim", False)
    return model.model_validate(cleaned)
