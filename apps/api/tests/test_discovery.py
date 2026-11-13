from __future__ import annotations

import pytest

from threatsight_api.config import Settings
from threatsight_api.discovery.extract import extract_page
from threatsight_api.discovery.pages import PAGES
from threatsight_api.discovery.robots import parse_robots
from threatsight_api.discovery.safety import DiscoverySafetyError, assert_scan_allowed, assert_url_allowed


def _settings(**kwargs) -> Settings:
    values = {
        "kill_switch": False,
        "sandbox_default": True,
        "demo_site_url": "http://demo-site:8091",
        "discovery_adapter": "inprocess",
    }
    values.update(kwargs)
    return Settings(**values)


def test_ssrf_and_scheme_rejects() -> None:
    settings = _settings()
    with pytest.raises(DiscoverySafetyError):
        assert_url_allowed("file:///etc/passwd", settings)
    with pytest.raises(DiscoverySafetyError):
        assert_url_allowed("gopher://demo-site:8091/", settings)
    with pytest.raises(DiscoverySafetyError):
        assert_url_allowed("http://127.0.0.1:8091/", settings)
    with pytest.raises(DiscoverySafetyError):
        assert_url_allowed("http://169.254.169.254/", settings)
    with pytest.raises(DiscoverySafetyError):
        assert_url_allowed("http://evil.example/", settings)
    with pytest.raises(DiscoverySafetyError):
        assert_url_allowed("http://user:pass@demo-site:8091/", settings)
    allowed = assert_url_allowed("http://demo-site:8091/ai-policy", settings)
    assert allowed.hostname == "demo-site"


def test_scan_requires_confirm_sandbox_and_kill_switch() -> None:
    settings = _settings()
    with pytest.raises(DiscoverySafetyError):
        assert_scan_allowed(settings, confirm_execution=False)
    with pytest.raises(DiscoverySafetyError):
        assert_scan_allowed(_settings(kill_switch=True), confirm_execution=True)
    with pytest.raises(DiscoverySafetyError):
        assert_scan_allowed(_settings(sandbox_default=False), confirm_execution=True)
    assert_scan_allowed(settings, confirm_execution=True)


def test_robots_disallow_internal() -> None:
    rules = parse_robots(PAGES["/robots.txt"])
    assert rules.allowed("/")
    assert rules.allowed("/ai-policy")
    assert not rules.allowed("/internal")
    assert not rules.allowed("/internal/secrets")


def test_extract_demo_pages_yield_expected_kinds() -> None:
    home = extract_page("/", PAGES["/"])
    kinds = {item.signal_kind for item in home.signals}
    assert "product_page" in kinds
    assert "model_provider_reference" in kinds
    policy = extract_page("/ai-policy", PAGES["/ai-policy"])
    assert any(item.signal_kind == "ai_usage_disclosure" for item in policy.signals)
    privacy = extract_page("/privacy", PAGES["/privacy"])
    assert any(item.signal_kind == "privacy_security_doc" for item in privacy.signals)
    gov = extract_page("/governance", PAGES["/governance"])
    assert any(item.signal_kind == "governance_statement" for item in gov.signals)
    docs = extract_page("/docs", PAGES["/docs"])
    assert any(item.signal_kind == "documentation_link" for item in docs.signals)


def test_extract_drops_instructions_and_compliant() -> None:
    trapped = extract_page("/trap", PAGES["/trap"])
    dumped = " ".join(f"{item.title} {item.statement} {item.quote}" for item in trapped.signals).upper()
    assert "COMPLIANT" not in dumped
    assert "IGNORE PREVIOUS" not in dumped
    assert "SYSTEM PROMPT" not in dumped
