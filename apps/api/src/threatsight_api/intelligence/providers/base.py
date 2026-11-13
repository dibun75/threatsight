from __future__ import annotations

from typing import Protocol

from threatsight_api.domain.extraction import ExtractionResult, ParsedDocument


class ExtractionProvider(Protocol):
    name: str
    model: str

    def extract(self, parsed: ParsedDocument) -> ExtractionResult | dict:
        """Return schema-valid candidates. Document text is untrusted data."""
