from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RobotsRules:
    allows: tuple[str, ...]
    disallows: tuple[str, ...]

    def allowed(self, path: str) -> bool:
        target = path or "/"
        allow_len = _longest_prefix(self.allows, target)
        deny_len = _longest_prefix(self.disallows, target)
        if deny_len == 0 and allow_len == 0:
            return True
        return allow_len >= deny_len


def parse_robots(text: str) -> RobotsRules:
    applies = False
    allows: list[str] = []
    disallows: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            applies = value in {"*", "threatsight-discovery"}
            continue
        if not applies:
            continue
        if key == "allow":
            allows.append(value or "/")
        elif key == "disallow":
            if value:
                disallows.append(value)
    return RobotsRules(tuple(allows), tuple(disallows))


def _longest_prefix(prefixes: tuple[str, ...], path: str) -> int:
    best = 0
    for prefix in prefixes:
        if prefix == "/":
            best = max(best, 1)
            continue
        if path == prefix or path.startswith(prefix.rstrip("/") + "/") or path.startswith(prefix):
            best = max(best, len(prefix))
    return best
