from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from threatsight_api.domain.freshness import classify_freshness
from threatsight_api.main import app
from threatsight_api.services.summary import build_executive_summary


def test_freshness_untested_without_timestamp() -> None:
    assert classify_freshness(None) == "UNTESTED"


def test_freshness_fresh_within_window() -> None:
    now = datetime(2026, 8, 27, tzinfo=UTC)
    observed = now - timedelta(days=7)
    assert classify_freshness(observed, now=now, window_days=30) == "FRESH"


def test_freshness_stale_outside_window() -> None:
    now = datetime(2026, 8, 27, tzinfo=UTC)
    observed = now - timedelta(days=31)
    assert classify_freshness(observed, now=now, window_days=30) == "STALE"


def test_freshness_treats_naive_datetime_as_utc() -> None:
    now = datetime(2026, 8, 27, tzinfo=UTC)
    observed = datetime(2026, 8, 20)
    assert classify_freshness(observed, now=now, window_days=30) == "FRESH"


def test_executive_summary_is_deterministic_and_never_compliant() -> None:
    summary = build_executive_summary(
        {
            "systems": {"count": 1},
            "controls": {"count": 2, "with_technical_verdict": 1, "by_assurance_status": {"GAP_DETECTED": 1}},
            "findings": {"high_or_critical_open": 1, "open": 1},
            "evidence_freshness": {"window_days": 30, "stale_controls": 0, "untested_controls": 1},
            "frameworks": {"mapped_items": 3, "item_count": 10},
        }
    )
    assert summary["llm_authored"] is False
    assert summary["narrative_authority"] == "deterministic_counts"
    assert summary["legal_compliance_claim"] is False
    assert "COMPLIANT" not in str(summary)
    assert any("GAP_DETECTED" in sentence for sentence in summary["sentences"])
    assert any("data origin" in sentence.lower() for sentence in summary["sentences"])
    assert any(link["href"] == "/showcase" for link in summary["links"])


def test_showcase_status_flags() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/showcase/status")
    assert response.status_code == 200
    body = response.json()
    assert body["legal_compliance_claim"] is False
    assert body["llm_authors_executive_summary"] is False
    assert body["autonomous_attack"] is False
    assert body["confirm_execution_required_for_auth01"] is True
    assert "COMPLIANT" not in response.text
    assert body["walkthrough"][0]["href"] == "/"
    assert body["guided_story"][0]["id"] == "system"
    assert body["scenario"]["company"] == "Nordic Retail AS"
    assert body["scenario"]["ai_system"] == "Customer Support AI Assistant"
    assert body["scenario"]["inventory_name"] == "Order support demo"
    assert body["scenario"]["labelled_synthetic"] is True
    assert body["scenario"]["legal_compliance_claim"] is False
    assert "Order support demo" in body["guided_story"][0]["body"]
    assert "Customer Support AI Assistant" in body["guided_story"][0]["body"]
    assert "second enterprise system" in body["guided_story"][0]["body"]
    assert [item["id"] for item in body["guided_story"]] == [
        "system",
        "risk",
        "failure",
        "evidence",
        "remediation",
        "retest",
        "explain",
    ]
    assert body["primary_loop"] == [
        "overview",
        "inventory",
        "requirements",
        "controls",
        "evidence",
        "tests",
        "findings",
        "remediation",
        "retest",
    ]
