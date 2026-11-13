import pytest

from threatsight_api.access import safe_return_path
from threatsight_api.activity.project import activity_view


def test_return_paths_stay_on_the_allowlist() -> None:
    assert safe_return_path("/demo") == "/demo"
    assert safe_return_path("/threats?view=world") == "/threats?view=world"
    assert safe_return_path("/services/1") == "/services/1"
    for value in ("https://evil.example", "//evil.example", "/ops", "/login", "/\\demo", "/threats?view=<script>"):
        with pytest.raises(ValueError):
            safe_return_path(value)


def test_activity_fixture_is_never_live() -> None:
    body = activity_view(window="24h", layer="all", direction="pair")
    assert body["live"] is False
    assert body["maturity"] == "fixture_tested"
    assert body["license"] == "not_approved_for_live_collection"
    assert "Synthetic demonstration" in body["label"]
    assert body["arcs"]
    empty = activity_view(window="7d", layer="all", direction="target")
    assert empty["locations"] == []
    assert empty["freshness"] == "unavailable"
    assert "score" not in body
