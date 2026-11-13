from threatsight_api.services.identity import (
    SHOWCASE_DISPLAY_NAME,
    SHOWCASE_ORG,
    display_name_for,
    identity_for,
    is_canonical_demo,
)
from types import SimpleNamespace

from threatsight_api.services.operations import _action_queue


def test_canonical_demo_uses_nordic_retail_display_name() -> None:
    assert is_canonical_demo("Order support demo", "lab") is True
    assert display_name_for("Order support demo", "lab") == SHOWCASE_DISPLAY_NAME
    ident = identity_for(SimpleNamespace(name="Order support demo", environment="lab", record_origin="showcase"))
    assert ident["organisation"] == SHOWCASE_ORG
    assert ident["technical_identifier"] == "Order support demo"
    assert ident["canonical_demo"] is True
    assert ident["supporting_inventory"] is False
    assert "COMPLIANT" not in str(ident)


def test_manual_system_keeps_its_name() -> None:
    ident = identity_for(SimpleNamespace(name="Finance bot", environment="prod", record_origin="manual"))
    assert ident["display_name"] == "Finance bot"
    assert ident["organisation"] is None
    assert ident["labelled_synthetic"] is False


def test_action_queue_links_latest_finding() -> None:
    items = _action_queue(
        systems=[SimpleNamespace(name="Order support demo")],
        high_count=2,
        gaps=0,
        untested=0,
        stale=0,
        pending_docs=0,
        findings=[SimpleNamespace(id="finding-1", verdict="FAIL")],
    )
    assert items[0]["href"] == "/findings/finding-1"
    assert "COMPLIANT" not in str(items)
