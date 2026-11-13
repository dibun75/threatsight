from __future__ import annotations

from threatsight_api.domain.extraction import (
    ExtractionResult,
    ParsedDocument,
    looks_like_instruction,
    validate_extraction_payload,
)
from threatsight_api.intelligence.providers.base import ExtractionProvider


def run_extraction(parsed: ParsedDocument, provider: ExtractionProvider) -> ExtractionResult:
    raw = provider.extract(parsed)
    if isinstance(raw, ExtractionResult):
        result = raw
    else:
        result = validate_extraction_payload(raw)
    kept = [
        candidate
        for candidate in result.candidates
        if not looks_like_instruction(candidate.title) and not looks_like_instruction(candidate.statement)
    ]
    warnings = list(result.warnings)
    if len(kept) != len(result.candidates):
        warnings.append("Dropped instruction-like candidates from untrusted document text")
    updates = {"candidates": kept, "warnings": warnings}
    if result.provider != provider.name:
        updates["provider"] = provider.name
        updates["model"] = provider.model
    return result.model_copy(update=updates)
