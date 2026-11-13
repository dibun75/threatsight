from __future__ import annotations

from types import SimpleNamespace

from threatsight_api.services.operations import _action_queue


def test_operations_action_queue_empty_inventory() -> None:
    items = _action_queue(systems=[], high_count=0, gaps=0, untested=0, stale=0, pending_docs=0)
    assert items[0]["href"] == "/showcase"
    assert "COMPLIANT" not in str(items)


def test_operations_action_queue_uses_counts() -> None:
    items = _action_queue(
        systems=[SimpleNamespace(name="Order support demo")],
        high_count=2,
        gaps=1,
        untested=3,
        stale=1,
        pending_docs=4,
    )
    assert items[0]["href"] == "/findings"
    assert len(items) == 1
    assert "need" in items[0]["detail"]
    assert "COMPLIANT" not in str(items)
