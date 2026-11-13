from __future__ import annotations

import re

from threatsight_api.domain.extraction import (
    ExtractedCandidate,
    ExtractionResult,
    ParsedDocument,
    SourceLocator,
    looks_like_instruction,
)

SENTENCE_RE = re.compile(
    r"([^.!?\n]{12,500}?\b(?:shall|must(?:\s+not)?|required to|is required to)\b[^.!?\n]{0,400}[.!?])",
    re.IGNORECASE,
)
CONTROL_RE = re.compile(
    r"^\s*(?:control|ctrl)\s*[:\-]\s*(?:(?P<ident>CTRL-[A-Z0-9_-]+)\s*[:\-]?\s*)?(?P<body>.+)$",
    re.IGNORECASE,
)
EVIDENCE_RE = re.compile(r"^\s*evidence\s*[:\-]\s*(?P<body>.+)$", re.IGNORECASE)
AI_SYSTEM_RE = re.compile(
    r"(?:the\s+)?([A-Za-z][A-Za-z0-9_-]{2,80})\s+AI\s+system"
    r"|\b(?:AI system|agent)\s+(?:named\s+)?[\"“]?([A-Za-z][A-Za-z0-9_-]{2,80})",
    re.IGNORECASE,
)


class HeuristicProvider:
    name = "heuristic"
    model = "rule-v1"

    def extract(self, parsed: ParsedDocument) -> ExtractionResult:
        candidates: list[ExtractedCandidate] = []
        warnings: list[str] = list(parsed.parse_warnings)
        seen: set[tuple[str, str]] = set()
        for location in parsed.locations:
            if looks_like_instruction(location.text):
                warnings.append(
                    f"Ignored instruction-like text in {location.section or 'document'} (untrusted input)"
                )
            for candidate in _from_location(location):
                key = (candidate.candidate_type, candidate.statement.lower())
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(candidate)
        if len(candidates) > 200:
            warnings.append("Heuristic extractor truncated candidates to 200")
            candidates = candidates[:200]
        return ExtractionResult(
            candidates=candidates,
            provider=self.name,
            model=self.model,
            warnings=warnings,
        )


def _from_location(location) -> list[ExtractedCandidate]:
    found: list[ExtractedCandidate] = []
    for raw_line in location.text.splitlines():
        line = raw_line.strip()
        if not line or looks_like_instruction(line):
            continue
        control_match = CONTROL_RE.match(line)
        if control_match:
            body = control_match.group("body").strip()
            ident = control_match.group("ident")
            title = ident or _title(body)
            found.append(
                _candidate(
                    "control",
                    title,
                    body,
                    0.72,
                    location,
                    line,
                )
            )
            continue
        evidence_match = EVIDENCE_RE.match(line)
        if evidence_match:
            body = evidence_match.group("body").strip()
            found.append(_candidate("evidence_statement", _title(body), body, 0.64, location, line))
            continue
        for match in AI_SYSTEM_RE.finditer(line):
            name = next((group for group in match.groups() if group), None)
            if not name:
                continue
            statement = f"Document references AI system '{name}'."
            found.append(_candidate("ai_system_reference", name, statement, 0.5, location, line))
        for sentence in SENTENCE_RE.findall(line if line.endswith((".", "!", "?")) else line + "."):
            text = sentence.strip()
            if looks_like_instruction(text):
                continue
            found.append(_candidate("requirement", _title(text), text, 0.58, location, text))
    if not found:
        for sentence in SENTENCE_RE.findall(location.text):
            text = sentence.strip()
            if looks_like_instruction(text):
                continue
            found.append(_candidate("requirement", _title(text), text, 0.55, location, text))
    return found


def _candidate(
    candidate_type: str,
    title: str,
    statement: str,
    confidence: float,
    location,
    quote: str,
) -> ExtractedCandidate:
    return ExtractedCandidate(
        candidate_type=candidate_type,  # type: ignore[arg-type]
        title=title[:200],
        statement=statement[:20000],
        confidence=confidence,
        locator=SourceLocator(
            page=location.page,
            section=location.section,
            start_char=location.start_char,
            end_char=location.end_char,
            quote=quote.strip()[:2000] or statement[:2000],
        ),
    )


def _title(text: str) -> str:
    clipped = re.sub(r"\s+", " ", text).strip()
    if len(clipped) <= 80:
        return clipped
    return clipped[:77].rstrip() + "..."
