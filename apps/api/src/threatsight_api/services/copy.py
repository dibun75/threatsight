from __future__ import annotations

ACTION_LABELS = {
    "enable_gateway_authorization": "Authorization gateway enabled",
}


def humanize_action(action: str | None) -> str:
    if not action:
        return ""
    if action in ACTION_LABELS:
        return ACTION_LABELS[action]
    return action.replace("_", " ").strip()


def counted(count: int, singular: str, plural: str | None = None, *, verb_one: str | None = None, verb_many: str | None = None) -> str:
    word = singular if count == 1 else (plural or f"{singular}s")
    phrase = f"{count} {word}"
    if verb_one or verb_many:
        phrase = f"{phrase} {verb_one if count == 1 else verb_many}"
    return phrase
