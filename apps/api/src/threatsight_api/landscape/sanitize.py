from __future__ import annotations

import html
import re

_TAGS = re.compile(r"<[^>]*>")
_SPACE = re.compile(r"\s+")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def plain(value: object, limit: int = 500) -> str:
    text = html.unescape(str(value or ""))
    text = _TAGS.sub(" ", text)
    text = _SPACE.sub(" ", text).strip()
    return text[:limit]


def safe_https(value: object) -> str | None:
    text = plain(value, 1000)
    if not text.startswith("https://") or any(mark in text for mark in ("<", ">", '"', "'", " ")):
        return None
    return text


def cve_list(values: object, limit: int = 20) -> list[str]:
    if not isinstance(values, list):
        return []
    found: list[str] = []
    for item in values:
        token = str(item or "").strip().upper()
        if _CVE.fullmatch(token) and token not in found:
            found.append(token)
        if len(found) >= limit:
            break
    return found
