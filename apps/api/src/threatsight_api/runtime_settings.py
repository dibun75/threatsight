"""Settings an administrator can change at runtime, on the web Settings page.

Only settings that are safe to change while the API runs are editable here: the AI provider for
documents and intelligence, its OpenAI-compatible endpoint, the evidence freshness window, the
upload limit, and the kill switch. Everything that decides how the platform starts or who may sign
in (database, sign-in, origins, sandboxing) stays in the environment, and the page shows it read-only.

Saved values live in the ``runtime_settings`` table and override the matching ``THREATSIGHT_*``
variable for the API and the worker. Clearing a value goes back to the variable. The API key is
write-only: reads report only whether one is set. The kill switch can only be added to: if the
environment turns it on, a saved "off" does not turn it off.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

TTL_SECONDS = 5.0
AUDIT_ENTITY = uuid.uuid5(uuid.NAMESPACE_URL, "threatsight:runtime-settings")


@dataclass(frozen=True)
class Spec:
    key: str
    label: str
    kind: str  # "choice", "text", "url", "secret", "int", "bool"
    help: str
    choices: tuple[str, ...] = ()
    minimum: int = 0
    maximum: int = 0
    group: str = "ai"


EDITABLE: dict[str, Spec] = {
    s.key: s
    for s in (
        Spec("intelligence_provider", "Threat intelligence summaries", "choice",
             "heuristic needs no model; openai sends text to the endpoint below.", ("heuristic", "openai")),
        Spec("extraction_provider", "Document extraction", "choice",
             "How requirements are pulled out of uploaded documents.", ("heuristic", "openai")),
        Spec("openai_base_url", "Endpoint base URL", "url",
             "Any OpenAI-compatible API: https://api.openai.com/v1, https://openrouter.ai/api/v1, or an Ollama server's /v1."),
        Spec("openai_model", "Model", "text", "For example gpt-4o-mini, openai/gpt-4o-mini on OpenRouter, or qwen2.5:7b-instruct on Ollama."),
        Spec("openai_api_key", "API key", "secret", "Stored on the server and never shown again. Ollama accepts any value."),
        Spec("evidence_fresh_days", "Evidence counts as fresh for (days)", "int",
             "Older evidence is shown as stale.", minimum=1, maximum=365, group="platform"),
        Spec("max_document_bytes", "Largest document upload (MB)", "int",
             "Between 1 MB and 50 MB.", minimum=1_048_576, maximum=52_428_800, group="platform"),
        Spec("kill_switch", "Kill switch", "bool",
             "Stops assurance runs, discovery and graph materialisation. Cannot override an environment that turns it on.",
             group="platform"),
    )
}

# Shown read-only: decided at deploy time, changed in .env (or the orchestrator) and a restart.
READ_ONLY = (
    ("env", "Environment"),
    ("deployment_profile", "Deployment profile"),
    ("auth_mode", "Sign-in mode"),
    ("public_origin", "Public address"),
    ("cors_origins", "Allowed browser origins"),
    ("sandbox_default", "Sandbox by default"),
    ("openapi_enabled", "API documentation (/docs)"),
    ("auth_session_minutes", "Session lifetime (minutes)"),
    ("auth_idle_minutes", "Idle sign-out (minutes)"),
    ("log_level", "Log level"),
    ("worker_poll_seconds", "Worker poll interval (seconds)"),
    ("assurance_adapter", "Assurance adapter"),
    ("discovery_adapter", "Discovery adapter"),
)

_lock = threading.Lock()
_cache: tuple[float, dict[str, Any]] | None = None


def clear_cache() -> None:
    global _cache
    with _lock:
        _cache = None


def _engine_if_ready():
    """The database engine, only if something already configured it. Never connects on its own."""
    from threatsight_api.persistence import session as db_session

    return db_session._engine


def overrides() -> dict[str, Any]:
    """Saved values, cached for a few seconds. Empty when no database is in use yet."""
    global _cache
    now = time.monotonic()
    with _lock:
        if _cache is not None and now - _cache[0] < TTL_SECONDS:
            return _cache[1]
    engine = _engine_if_ready()
    values: dict[str, Any] = {}
    if engine is not None:
        try:
            with engine.connect() as conn:
                rows = conn.execute(text("SELECT key, value FROM runtime_settings")).all()
            for key, raw in rows:
                if key in EDITABLE:
                    try:
                        values[key] = json.loads(raw)
                    except ValueError:
                        continue
        except Exception:  # table not migrated yet, database down: fall back to the environment
            values = {}
    with _lock:
        _cache = (now, values)
    return values


def merge(base, values: dict[str, Any]):
    """The environment settings with saved values applied."""
    if not values:
        return base
    update = {k: v for k, v in values.items() if k in EDITABLE}
    if "kill_switch" in update:
        update["kill_switch"] = bool(base.kill_switch or update["kill_switch"])
    return base.model_copy(update=update)


def validate(key: str, value: Any) -> Any:
    spec = EDITABLE.get(key)
    if spec is None:
        raise ValueError(f"{key} cannot be changed here")
    if spec.kind == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"{spec.label} must be true or false")
        return value
    if spec.kind == "int":
        if isinstance(value, bool) or not isinstance(value, int) or not spec.minimum <= value <= spec.maximum:
            raise ValueError(f"{spec.label} must be a whole number from {spec.minimum} to {spec.maximum}")
        return value
    cleaned = str(value).strip()
    if spec.kind == "choice":
        if cleaned not in spec.choices:
            raise ValueError(f"{spec.label} must be one of {', '.join(spec.choices)}")
        return cleaned
    if spec.kind == "url":
        parts = urlsplit(cleaned)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.fragment or len(cleaned) > 300:
            raise ValueError("Endpoint must be an http(s) address without a user, password or fragment")
        return cleaned.rstrip("/")
    if not cleaned or len(cleaned) > (500 if spec.kind == "secret" else 120) or any(ord(c) < 32 for c in cleaned):
        raise ValueError(f"{spec.label} is empty or too long")
    return cleaned


def save(db: Session, changes: dict[str, Any], actor: str) -> list[str]:
    """Write changes. A value of None clears the saved value. Returns the keys that changed."""
    from threatsight_api.persistence.settings_models import RuntimeSetting

    clean: dict[str, Any] = {}
    for key, value in changes.items():
        clean[key] = None if value is None or value == "" else validate(key, value)
    changed: list[str] = []
    for key, value in clean.items():
        row = db.get(RuntimeSetting, key)
        if value is None:
            if row is not None:
                db.delete(row)
                changed.append(key)
            continue
        raw = json.dumps(value)
        if row is None:
            db.add(RuntimeSetting(key=key, value=raw, updated_by=actor[:200]))
        elif row.value != raw:
            row.value, row.updated_by = raw, actor[:200]
            row.updated_at = func.now()  # type: ignore[assignment]
        else:
            continue
        changed.append(key)
    db.flush()
    clear_cache()
    return changed


def view(db: Session, base) -> dict[str, Any]:
    """Editable and read-only settings for the page. Secrets are reported as set or not set.

    Values come from this session, so a change not yet committed is already shown.
    """
    from threatsight_api.persistence.settings_models import RuntimeSetting

    rows = {r.key: r for r in db.scalars(select(RuntimeSetting)).all() if r.key in EDITABLE}
    effective = merge(base, {k: json.loads(r.value) for k, r in rows.items()})
    items = []
    for key, spec in EDITABLE.items():
        row = rows.get(key)
        current = getattr(effective, key)
        env_value = getattr(base, key)
        item: dict[str, Any] = {
            "key": key, "label": spec.label, "kind": spec.kind, "help": spec.help, "group": spec.group,
            "choices": list(spec.choices), "minimum": spec.minimum or None, "maximum": spec.maximum or None,
            "source": "saved" if row else "environment", "env_var": f"THREATSIGHT_{key.upper()}",
            "updated_by": row.updated_by if row else None,
            "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
        }
        if spec.kind == "secret":
            item["is_set"] = bool(str(current or "").strip())
            item["env_is_set"] = bool(str(env_value or "").strip())
        else:
            item["value"] = current
            item["env_value"] = env_value
        items.append(item)
    fixed = []
    for key, label in READ_ONLY:
        value = getattr(base, key, None)
        fixed.append({"key": key, "label": label, "value": value, "env_var": f"THREATSIGHT_{key.upper()}"})
    db_host = urlsplit(base.database_url).hostname or ""
    fixed.append({"key": "database", "label": "Database host", "value": db_host, "env_var": "THREATSIGHT_DATABASE_URL"})
    return {"editable": items, "fixed": fixed}
