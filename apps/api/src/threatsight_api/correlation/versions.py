"""Bounded dotted-numeric versions. Unsupported notation stays unknown."""

from __future__ import annotations

from threatsight_api.correlation.bounds import MAX_VERSION_LENGTH

COMPARATOR = "numeric-dotted-v1"


def parse_version(value: object) -> tuple[int, ...] | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_VERSION_LENGTH or text.count(".") > 7:
        return None
    if text[:1].lower() == "v" and "." in text:
        text = text[1:]
    parts = text.split(".")
    numbers: list[int] = []
    for part in parts:
        if not part or len(part) > 8 or any(ch < "0" or ch > "9" for ch in part):
            return None
        numbers.append(int(part))
    return tuple(numbers)


def parse_range(value: object) -> list[tuple[str, tuple[int, ...]]] | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_VERSION_LENGTH or text.count(",") > 3:
        return None
    pieces: list[tuple[str, tuple[int, ...]]] = []
    for raw in text.split(","):
        item = raw.strip()
        operator = next((op for op in (">=", "<=", ">", "<", "=") if item.startswith(op)), "")
        if not operator:
            return None
        version = parse_version(item[len(operator):])
        if version is None:
            return None
        pieces.append((operator, version))
    return pieces


def range_is_complete(pieces: list[tuple[str, tuple[int, ...]]]) -> bool:
    operators = {item[0] for item in pieces}
    has_lower = bool(operators & {">=", ">", "="})
    has_upper = bool(operators & {"<=", "<", "="})
    return has_lower and has_upper


def compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    a = left + (0,) * (width - len(left))
    b = right + (0,) * (width - len(right))
    return (a > b) - (a < b)


def version_relation(version: tuple[int, ...], pieces: list[tuple[str, tuple[int, ...]]]) -> str:
    for operator, bound in pieces:
        order = compare(version, bound)
        if operator == "=" and order != 0:
            return "outside"
        if operator == ">" and order <= 0:
            return "outside"
        if operator == ">=" and order < 0:
            return "outside"
        if operator == "<" and order >= 0:
            return "outside"
        if operator == "<=" and order > 0:
            return "outside"
    return "inside"
