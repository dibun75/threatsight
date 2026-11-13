from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threatsight_api.threats.catalog import SOURCE_KINDS, technique_for

FORBIDDEN_KEYS = frozenset({"fetch", "crawl", "scrape", "attack", "exploit", "payload", "execute"})


class IntelIngestError(ValueError):
    pass


class AdvisoryIngest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]{1,62}$")
    title: str = Field(min_length=3, max_length=200)
    summary: str = Field(min_length=8, max_length=2000)
    locator: str = Field(min_length=12, max_length=500)
    source_kind: str = Field(min_length=2, max_length=32)
    technique_keys: list[str] = Field(min_length=1, max_length=20)

    @field_validator("locator")
    @classmethod
    def https_locator(cls, value: str) -> str:
        locator = value.strip()
        if not locator.startswith("https://"):
            raise ValueError("locator must be an https URL")
        if any(token in locator.lower() for token in ("localhost", "127.0.0.1", "0.0.0.0", "169.254.", "[::1]")):
            raise ValueError("locator must be a public https URL")
        return locator

    @field_validator("source_kind")
    @classmethod
    def known_source(cls, value: str) -> str:
        kind = value.strip().lower()
        if kind not in SOURCE_KINDS:
            raise ValueError("unknown source_kind")
        return kind

    @field_validator("title", "summary")
    @classmethod
    def no_compliance_claim(cls, value: str) -> str:
        if "COMPLIANT" in value.upper():
            raise ValueError("ingestion cannot claim legal compliance")
        return value.strip()

    @field_validator("technique_keys")
    @classmethod
    def known_techniques(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in values:
            key = raw.strip()
            if technique_for(key) is None:
                raise ValueError(f"unknown technique_key: {key}")
            if key not in cleaned:
                cleaned.append(key)
        if not cleaned:
            raise ValueError("technique_keys required")
        return cleaned


def reject_forbidden_payload(raw: dict) -> None:
    extra = FORBIDDEN_KEYS.intersection(raw)
    if extra:
        raise IntelIngestError("ingestion does not fetch, crawl, or execute attacks")


def parse_advisory(raw: dict) -> AdvisoryIngest:
    reject_forbidden_payload(raw)
    try:
        return AdvisoryIngest.model_validate(raw)
    except Exception as exc:
        raise IntelIngestError(str(exc)) from exc
