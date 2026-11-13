"""Settings page: runtime settings a platform administrator can change. Tokens never qualify."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from threatsight_api import runtime_settings
from threatsight_api.api.deps import DbSession
from threatsight_api.config import base_settings, get_settings
from threatsight_api.services.audit import record_audit

router = APIRouter(tags=["settings"])


def _admin(request: Request) -> str:
    if getattr(request.state, "role", "") != "platform-admin" or getattr(request.state, "via_api_token", False):
        raise HTTPException(status_code=403, detail="Only a platform administrator can change settings")
    return str(getattr(request.state, "actor", "") or "admin")


class SettingsBody(BaseModel):
    # key -> new value; null or "" goes back to the environment value
    values: dict[str, Any]


@router.get("/settings")
def read_settings(request: Request, db: DbSession) -> dict:
    _admin(request)
    runtime_settings.clear_cache()
    return runtime_settings.view(db, base_settings())


@router.patch("/settings")
def change_settings(body: SettingsBody, request: Request, db: DbSession) -> dict:
    actor = _admin(request)
    try:
        changed = runtime_settings.save(db, body.values, actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if changed:
        # Record which settings changed, never their values (one of them is an API key).
        record_audit(db, entity_type="runtime_settings", entity_id=runtime_settings.AUDIT_ENTITY, action="updated", actor=actor,
                     payload={"keys": changed})
    view = runtime_settings.view(db, base_settings())
    db.commit()  # commit before dropping the cache, so the next read sees the new values
    runtime_settings.clear_cache()
    return {**view, "changed": changed}


class ProbeBody(BaseModel):
    base_url: str | None = None
    api_key: str | None = None


@router.post("/settings/ai/test")
def test_ai_endpoint(body: ProbeBody, request: Request) -> dict:
    """List the models at the document-AI endpoint, to confirm the address and key work.

    Without a key in the body the saved key is used, but only for the saved address.
    """
    _admin(request)
    current = get_settings()
    try:
        base = runtime_settings.validate("openai_base_url", body.base_url or current.openai_base_url)
    except ValueError as exc:
        return {"reachable": False, "models": [], "error": str(exc)}
    key = (body.api_key or "").strip() or (current.openai_api_key if base == current.openai_base_url.rstrip("/") else "")
    req = urllib.request.Request(f"{base}/models", headers={"Authorization": f"Bearer {key}"} if key else {})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:  # noqa: S310 - administrator-chosen endpoint
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        hint = " Check the API key." if exc.code in {401, 403} else " Check that the address ends in /v1."
        return {"reachable": False, "models": [], "error": f"{base}/models answered HTTP {exc.code}.{hint}"}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {"reachable": False, "models": [], "error": f"The API could not reach {base}: {getattr(exc, 'reason', exc)}"}
    names = [str(m.get("id", "")) for m in (data.get("data") or []) if isinstance(m, dict)] if isinstance(data, dict) else []
    return {"reachable": True, "models": sorted(n for n in names if n)[:500], "error": None}
