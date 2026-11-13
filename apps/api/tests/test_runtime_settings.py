"""Settings page: runtime overrides of THREATSIGHT_* values, editable by a platform administrator."""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from threatsight_api import runtime_settings
from threatsight_api.config import Settings, base_settings, get_settings

LIVE = os.environ.get("THREATSIGHT_TEST_USE_LIVE_DB", "").lower() in {"1", "true", "yes"}
ADMIN = {"X-Role": "platform-admin", "X-Actor": "settings-admin"}


def test_validation_refuses_bad_values() -> None:
    assert runtime_settings.validate("openai_base_url", "https://openrouter.ai/api/v1/") == "https://openrouter.ai/api/v1"
    assert runtime_settings.validate("intelligence_provider", "openai") == "openai"
    assert runtime_settings.validate("evidence_fresh_days", 14) == 14
    for key, value in (
        ("database_url", "postgresql://x"),
        ("auth_mode", "development"),
        ("intelligence_provider", "magic"),
        ("openai_base_url", "file:///etc/passwd"),
        ("openai_base_url", "https://user:pw@example.com/v1"),
        ("evidence_fresh_days", 0),
        ("evidence_fresh_days", True),
        ("max_document_bytes", 10),
        ("kill_switch", "yes"),
        ("openai_api_key", "x" * 501),
        ("openai_model", "a\nb"),
    ):
        with pytest.raises(ValueError):
            runtime_settings.validate(key, value)


def test_merge_applies_saved_values_and_never_lifts_an_environment_kill_switch() -> None:
    base = Settings(kill_switch=False, openai_model="gpt-4o-mini")
    merged = runtime_settings.merge(base, {"openai_model": "openai/gpt-4o-mini", "kill_switch": True, "database_url": "x"})
    assert merged.openai_model == "openai/gpt-4o-mini" and merged.kill_switch is True and merged.database_url == base.database_url
    stopped = Settings(kill_switch=True)
    assert runtime_settings.merge(stopped, {"kill_switch": False}).kill_switch is True


def test_without_a_database_the_environment_is_used() -> None:
    get_settings.cache_clear()
    assert get_settings().model_dump() == base_settings().model_dump()


@pytest.mark.skipif(not LIVE, reason="requires postgres")
def test_admin_saves_reads_and_clears_settings() -> None:
    from threatsight_api.main import app

    with TestClient(app) as client:
        assert client.get("/api/v1/settings", headers={"X-Role": "operator", "X-Actor": "op"}).status_code == 403
        assert client.patch("/api/v1/settings", json={"values": {"kill_switch": True}}, headers={"X-Role": "operator", "X-Actor": "op"}).status_code == 403

        view = client.get("/api/v1/settings", headers=ADMIN).json()
        keys = {item["key"] for item in view["editable"]}
        assert {"openai_api_key", "intelligence_provider", "kill_switch"} <= keys and "database_url" not in keys
        assert any(item["key"] == "auth_mode" for item in view["fixed"])
        assert "changeme" not in json.dumps(view)

        r = client.patch("/api/v1/settings", headers=ADMIN, json={"values": {
            "intelligence_provider": "openai", "openai_base_url": "https://openrouter.ai/api/v1",
            "openai_model": "openai/gpt-4o-mini", "openai_api_key": "sk-or-secret-42", "evidence_fresh_days": 14}})
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body["changed"]) == {"intelligence_provider", "openai_base_url", "openai_model", "openai_api_key", "evidence_fresh_days"}
        assert "sk-or-secret-42" not in r.text
        by_key = {item["key"]: item for item in body["editable"]}
        assert by_key["openai_api_key"]["is_set"] is True and by_key["evidence_fresh_days"]["value"] == 14
        assert by_key["openai_model"]["source"] == "saved" and by_key["openai_model"]["updated_by"] == "settings-admin"

        settings = get_settings()
        assert settings.intelligence_provider == "openai" and settings.openai_api_key == "sk-or-secret-42"
        assert client.get("/api/v1/security/status", headers=ADMIN).json()["intelligence_provider"] == "openai"

        assert client.patch("/api/v1/settings", headers=ADMIN, json={"values": {"evidence_fresh_days": 9999}}).status_code == 400
        assert client.patch("/api/v1/settings", headers=ADMIN, json={"values": {"database_url": "x"}}).status_code == 400

        cleared = client.patch("/api/v1/settings", headers=ADMIN, json={"values": {k: None for k in runtime_settings.EDITABLE}}).json()
        assert all(item["source"] == "environment" for item in cleared["editable"])
        assert get_settings().intelligence_provider == base_settings().intelligence_provider
