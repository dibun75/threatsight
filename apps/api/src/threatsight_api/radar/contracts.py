from __future__ import annotations

from datetime import datetime
from typing import Literal
import uuid

from pydantic import BaseModel, Field, HttpUrl, field_validator


class NormalizedThreatEvent(BaseModel):
    external_id: str = Field(min_length=1, max_length=200)
    event_type: Literal["advisory", "vulnerability", "campaign", "incident_report", "national_risk_level_change"]
    title: str = Field(min_length=1, max_length=500)
    summary: str = Field(min_length=1, max_length=20_000)
    canonical_url: HttpUrl
    published_at: datetime | None = None
    source_updated_at: datetime | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    countries: list[str] = Field(default_factory=list)
    authority_jurisdictions: list[str] = Field(default_factory=list)
    target_countries: list[str] = Field(default_factory=list)
    victim_countries: list[str] = Field(default_factory=list)
    infrastructure_countries: list[str] = Field(default_factory=list)
    prevalence_countries: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    vendors: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    exploitation_status: Literal["unknown", "not_observed", "suspected", "proof_of_concept", "known_exploited"] = "unknown"
    source_payload_hash: str = Field(default="", max_length=64)
    parser_version: str = Field(default="phase1-v1", min_length=1, max_length=64)
    provenance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list, max_length=20)
    attributes: dict = Field(default_factory=dict)

    @field_validator(
        "countries",
        "authority_jurisdictions",
        "target_countries",
        "victim_countries",
        "infrastructure_countries",
        "prevalence_countries",
        "sectors",
        "vendors",
        "products",
        "technologies",
        "cves",
    )
    @classmethod
    def normalize_tags(cls, values: list[str]) -> list[str]:
        cleaned = {str(value).strip() for value in values if str(value).strip()}
        return sorted(cleaned, key=str.casefold)


class OrganizationProfileIn(BaseModel):
    countries: list[str] = Field(default_factory=list, max_length=100)
    sectors: list[str] = Field(default_factory=list, max_length=100)
    vendors: list[str] = Field(default_factory=list, max_length=500)
    products: list[str] = Field(default_factory=list, max_length=1000)
    technologies: list[str] = Field(default_factory=list, max_length=500)
    critical_services: list[str] = Field(default_factory=list, max_length=200)
    minimum_relevance: int = Field(default=20, ge=0, le=100)

    @field_validator("countries", "sectors", "vendors", "products", "technologies", "critical_services")
    @classmethod
    def normalize_profile_tags(cls, values: list[str]) -> list[str]:
        cleaned = {str(value).strip() for value in values if str(value).strip()}
        return sorted(cleaned, key=str.casefold)


class RelevanceResult(BaseModel):
    score: int = Field(ge=0, le=100)
    level: str
    reasons: list[str]
    matches: dict[str, list[str]]


class ManualThreatEventIn(BaseModel):
    external_id: str = Field(min_length=1, max_length=200)
    event_type: Literal["advisory", "vulnerability", "campaign", "incident_report", "national_risk_level_change"]
    title: str = Field(min_length=1, max_length=500)
    summary: str = Field(min_length=1, max_length=2_000)
    canonical_url: HttpUrl
    published_at: datetime | None = None
    source_updated_at: datetime | None = None
    target_countries: list[str] = Field(default_factory=list, max_length=20)
    victim_countries: list[str] = Field(default_factory=list, max_length=20)
    sectors: list[str] = Field(default_factory=list, max_length=50)
    vendors: list[str] = Field(default_factory=list, max_length=50)
    products: list[str] = Field(default_factory=list, max_length=100)
    technologies: list[str] = Field(default_factory=list, max_length=50)
    cves: list[str] = Field(default_factory=list, max_length=100)
    exploitation_status: Literal["unknown", "not_observed", "suspected", "proof_of_concept", "known_exploited"] = "unknown"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list, max_length=20)


class RadarFilterSchema(BaseModel):
    country: str | None = Field(default=None, min_length=2, max_length=2)
    geography: Literal["any", "authority", "target", "victim", "infrastructure", "prevalence"] = "any"
    sector: str | None = Field(default=None, max_length=100)
    vendor: str | None = Field(default=None, max_length=100)
    product: str | None = Field(default=None, max_length=200)
    technology: str | None = Field(default=None, max_length=100)
    event_type: Literal["advisory", "vulnerability", "campaign", "incident_report", "national_risk_level_change"] | None = None
    source: str | None = Field(default=None, max_length=64)
    published_after: datetime | None = None
    published_before: datetime | None = None
    minimum_relevance: int | None = Field(default=None, ge=0, le=100)
    relevance: Literal["none", "low", "medium", "high", "critical"] | None = None
    exploitation_status: Literal["unknown", "not_observed", "suspected", "proof_of_concept", "known_exploited"] | None = None
    sort: Literal["published_at", "updated_at", "relevance"] = "published_at"
    direction: Literal["asc", "desc"] = "desc"
    page: int = Field(default=1, ge=1, le=1000)
    limit: int = Field(default=50, ge=1, le=100)


class SavedViewIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    filters: RadarFilterSchema


class TriageIn(BaseModel):
    status: Literal["new", "reviewing", "action_required", "monitoring", "resolved", "dismissed"]
    priority: Literal["unassigned", "low", "medium", "high", "urgent"]
    owner: str | None = Field(default=None, max_length=200)
    due_at: datetime | None = None
    rationale: str = Field(min_length=1, max_length=2_000)


class BusinessServiceIn(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2_000)
    criticality: Literal["unknown", "low", "medium", "high", "critical"] = "unknown"


class ResourceBindingIn(BaseModel):
    resource_type: Literal["control", "evidence", "system"]
    resource_id: uuid.UUID


class ReadinessLinkIn(BaseModel):
    target_type: Literal["control", "evidence", "system", "business_service"]
    target_id: uuid.UUID
    reason: str = Field(min_length=1, max_length=2_000)
    provenance: str = Field(min_length=1, max_length=500)
    limitations: list[str] = Field(default_factory=list, max_length=20)
