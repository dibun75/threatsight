from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threatsight_api.domain.assurance import FORBIDDEN_ASSURANCE_LABELS

CANDIDATE_TYPES = ("requirement", "control", "evidence_statement", "ai_system_reference")
CandidateType = Literal["requirement", "control", "evidence_statement", "ai_system_reference"]
ReviewStatus = Literal["pending", "approved", "rejected", "needs_revision"]
MediaKind = Literal["pdf", "docx", "text", "markdown"]
MappingAction = Literal["link_existing", "propose_new", "reject"]

INSTRUCTION_RE = re.compile(
    r"(ignore\s+(all\s+|any\s+)?previous\s+instructions"
    r"|you\s+are\s+now\b"
    r"|system\s+prompt"
    r"|override\s+(the\s+)?(system|policy|extractor)"
    r"|set\s+(all\s+)?candidates?\s+to\s+approved"
    r"|review_status\s*[:=]\s*approved"
    r"|grant\s+(yourself\s+)?(network|tool|root)\s+access"
    r"|execute(?:\s+the)?\s+(tool|command|code)"
    r"|call\s+the\s+\w+\s+(api|tool)"
    r"|rm\s+-rf"
    r"|authorize\s+tools?)",
    re.IGNORECASE,
)

TITLE = Field(min_length=1, max_length=200)
STATEMENT = Field(min_length=1, max_length=20000)
QUOTE = Field(min_length=1, max_length=2000)


class StrictExtract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceLocator(StrictExtract):
    page: int | None = Field(default=None, ge=1, le=100000)
    section: str | None = Field(default=None, max_length=300)
    start_char: int | None = Field(default=None, ge=0)
    end_char: int | None = Field(default=None, ge=0)
    quote: str = QUOTE


class ExtractedCandidate(StrictExtract):
    candidate_type: CandidateType
    title: str = TITLE
    statement: str = STATEMENT
    confidence: float = Field(ge=0, le=1)
    locator: SourceLocator

    @field_validator("title", "statement")
    @classmethod
    def reject_compliance_and_authority(cls, value: str) -> str:
        compact = value.strip()
        if compact.upper() in FORBIDDEN_ASSURANCE_LABELS:
            raise ValueError("Extraction must not emit a legal-compliance label")
        return compact


class ExtractionResult(StrictExtract):
    candidates: list[ExtractedCandidate] = Field(default_factory=list, max_length=200)
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    warnings: list[str] = Field(default_factory=list, max_length=50)


class DocumentLocation(BaseModel):
    page: int | None = None
    section: str | None = None
    text: str
    start_char: int
    end_char: int


class ParsedDocument(BaseModel):
    media_kind: MediaKind
    content_type: str
    filename: str
    content_hash: str
    byte_size: int
    extracted_text: str
    locations: list[DocumentLocation]
    page_count: int | None = None
    parse_warnings: list[str] = Field(default_factory=list)


def looks_like_instruction(text: str) -> bool:
    return bool(INSTRUCTION_RE.search(text))


def validate_extraction_payload(payload: object) -> ExtractionResult:
    if not isinstance(payload, dict):
        raise ValueError("Extraction payload must be an object")
    allowed = {"candidates", "provider", "model", "warnings"}
    cleaned = {key: payload[key] for key in allowed if key in payload}
    raw_candidates = cleaned.get("candidates", [])
    if not isinstance(raw_candidates, list):
        raise ValueError("candidates must be a list")
    sanitized: list[dict] = []
    for item in raw_candidates:
        if not isinstance(item, dict):
            raise ValueError("each candidate must be an object")
        locator = item.get("locator") if isinstance(item.get("locator"), dict) else {}
        sanitized.append(
            {
                "candidate_type": item.get("candidate_type"),
                "title": item.get("title"),
                "statement": item.get("statement"),
                "confidence": item.get("confidence"),
                "locator": {
                    "page": locator.get("page"),
                    "section": locator.get("section"),
                    "start_char": locator.get("start_char"),
                    "end_char": locator.get("end_char"),
                    "quote": locator.get("quote"),
                },
            }
        )
    cleaned["candidates"] = sanitized
    result = ExtractionResult.model_validate(cleaned)
    for candidate in result.candidates:
        if looks_like_instruction(candidate.title) or looks_like_instruction(candidate.statement):
            raise ValueError("Extraction must not treat document instructions as system commands")
    return result


def utc_now() -> datetime:
    from datetime import UTC

    return datetime.now(UTC)
