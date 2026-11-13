from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

from threatsight_api.domain.assurance import FORBIDDEN_ASSURANCE_LABELS
from threatsight_api.domain.extraction import looks_like_instruction

SIGNAL_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ai_usage_disclosure", ("we use an ai", "ai usage disclosure", "usage disclosure")),
    ("product_page", ("ai-powered product", "ai order assistant", "northwind copilot")),
    ("privacy_security_doc", ("privacy and security documentation", "privacy and security")),
    ("model_provider_reference", ("northwind-lm", "hosted by democloud", "model hosted")),
    ("governance_statement", ("human review is required", "governance statement")),
    ("documentation_link", ("operator documentation", "documentation for")),
)

PATH_ASSET_KIND = {
    "/": "product_page",
    "/ai-policy": "policy",
    "/privacy": "privacy_security_doc",
    "/governance": "governance_page",
    "/docs": "documentation",
}

COMPLIANT_RE = re.compile(r"\bCOMPLIANT\b", re.IGNORECASE)


@dataclass
class ParsedPage:
    title: str
    headings: list[str]
    paragraphs: list[str]
    links: list[tuple[str, str]]


@dataclass
class ExtractedSignal:
    signal_kind: str
    title: str
    statement: str
    quote: str


@dataclass
class ExtractedAsset:
    kind: str
    title: str
    summary: str
    signals: list[ExtractedSignal] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.headings: list[str] = []
        self.paragraphs: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._capture: str | None = None
        self._buf: list[str] = []
        self._href: str | None = None
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._skip = True
            return
        if tag == "title":
            self._capture = "title"
            self._buf = []
        elif tag in {"h1", "h2"}:
            self._capture = "heading"
            self._buf = []
        elif tag == "p":
            self._capture = "p"
            self._buf = []
        elif tag == "a":
            self._capture = "a"
            self._buf = []
            self._href = dict(attrs).get("href")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._skip = False
            return
        text = "".join(self._buf).strip()
        if tag == "title" and self._capture == "title":
            self.title_parts.append(text)
        elif tag in {"h1", "h2"} and self._capture == "heading" and text:
            self.headings.append(text)
        elif tag == "p" and self._capture == "p" and text:
            self.paragraphs.append(text)
        elif tag == "a" and self._capture == "a":
            self.links.append((self._href or "", text))
        self._capture = None
        self._buf = []
        self._href = None

    def handle_data(self, data: str) -> None:
        if self._skip or self._capture is None:
            return
        self._buf.append(data)


def parse_html(html: str) -> ParsedPage:
    parser = _Collector()
    parser.feed(html)
    return ParsedPage(
        title=" ".join(part for part in parser.title_parts if part).strip(),
        headings=parser.headings,
        paragraphs=parser.paragraphs,
        links=parser.links,
    )


def extract_page(url_path: str, html: str) -> ExtractedAsset:
    parsed = parse_html(html)
    title = (parsed.title or (parsed.headings[0] if parsed.headings else url_path))[:200]
    summary = (parsed.paragraphs[0] if parsed.paragraphs else title)[:2000]
    kind = PATH_ASSET_KIND.get(url_path or "/", "product_page")
    if "copilot" in title.lower() or "assistant" in title.lower():
        if kind == "product_page":
            kind = "product_page"
    blobs = [parsed.title, *parsed.headings, *parsed.paragraphs]
    signals: list[ExtractedSignal] = []
    seen_kinds: set[str] = set()
    for blob in blobs:
        if _is_unsafe_text(blob):
            continue
        lowered = blob.lower()
        for signal_kind, needles in SIGNAL_RULES:
            if signal_kind in seen_kinds:
                continue
            if any(needle in lowered for needle in needles):
                seen_kinds.add(signal_kind)
                signals.append(
                    ExtractedSignal(
                        signal_kind=signal_kind,
                        title=_title_for(signal_kind, parsed.title or blob)[:200],
                        statement=blob[:20000],
                        quote=blob[:400],
                    )
                )
    for href, text in parsed.links:
        combined = f"{text} {href}".lower()
        if _is_unsafe_text(text):
            continue
        if "documentation_link" in seen_kinds:
            break
        if "doc" in combined or href.rstrip("/") == "/docs":
            seen_kinds.add("documentation_link")
            label = text or href
            signals.append(
                ExtractedSignal(
                    signal_kind="documentation_link",
                    title="Documentation link",
                    statement=f"Public documentation link: {label}",
                    quote=label[:400],
                )
            )
    return ExtractedAsset(
        kind=kind,
        title=title[:200] or url_path,
        summary=summary,
        signals=signals,
        links=[href for href, _text in parsed.links if href],
    )


def _title_for(kind: str, fallback: str) -> str:
    labels = {
        "ai_usage_disclosure": "AI usage disclosure",
        "product_page": "AI product page",
        "privacy_security_doc": "Privacy and security documentation",
        "model_provider_reference": "Model or provider reference",
        "governance_statement": "Governance statement",
        "documentation_link": "Documentation link",
    }
    return labels.get(kind, fallback or kind)


def _is_unsafe_text(text: str) -> bool:
    compact = text.strip()
    if not compact:
        return True
    if compact.upper() in FORBIDDEN_ASSURANCE_LABELS:
        return True
    if COMPLIANT_RE.search(compact):
        return True
    return looks_like_instruction(compact)
