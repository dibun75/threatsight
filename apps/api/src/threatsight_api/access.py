"""Return-path checks for login. This module does not read configuration values."""

from __future__ import annotations

ALLOWED_RETURN_PREFIXES = (
    "/demo",
    "/threats",
    "/services",
    "/paths",
    "/controls",
    "/actions",
    "/evidence",
    "/briefing",
    "/tour",
)


def safe_return_path(value: str) -> str:
    """Accept only a relative path on the product allowlist."""
    if not value or len(value) > 500:
        raise ValueError("invalid return path")
    if not value.startswith("/") or value.startswith("//") or "\\" in value or "://" in value:
        raise ValueError("invalid return path")
    path, separator, query = value.partition("?")
    if path != "/" and not any(path == prefix or path.startswith(f"{prefix}/") for prefix in ALLOWED_RETURN_PREFIXES):
        raise ValueError("invalid return path")
    if separator and not query:
        raise ValueError("invalid return path")
    if query and any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=&_.-" for character in query):
        raise ValueError("invalid return path")
    return value
