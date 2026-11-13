from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from threatsight_api.connectivity.contract import ConnectivityIngestError
from threatsight_api.connectivity.ingest import ingest_event


class _FakeSystem:
    def __init__(self) -> None:
        self.id = uuid.uuid4()


class _FakeDb:
    def __init__(self, system=None) -> None:
        self.system = system
        self.added = []

    def get(self, model, ident):
        if self.system is not None and ident == self.system.id:
            return self.system
        return None

    def add(self, obj) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        if self.added and getattr(self.added[-1], "id", None) is None:
            self.added[-1].id = uuid.uuid4()


def test_ingest_rejects_unknown_source_and_firewall_fields() -> None:
    db = _FakeDb(_FakeSystem())
    with pytest.raises(ConnectivityIngestError, match="source_kind"):
        ingest_event(db, "operator", {"ai_system_id": db.system.id, "source_kind": "siem"})
    with pytest.raises(ConnectivityIngestError, match="runtime firewall"):
        ingest_event(
            db,
            "operator",
            {"ai_system_id": db.system.id, "source_kind": "gateway", "runtime_firewall": True},
        )


def test_ingest_rejects_missing_system() -> None:
    db = _FakeDb()
    with pytest.raises(ConnectivityIngestError, match="not found"):
        ingest_event(db, "operator", {"ai_system_id": uuid.uuid4(), "source_kind": "sdk"})


def test_ingest_accepts_gateway_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    from threatsight_api.connectivity import ingest as ingest_mod

    recorded = []

    def fake_audit(*args, **kwargs):
        recorded.append(kwargs)
        return None

    monkeypatch.setattr(ingest_mod, "record_audit", fake_audit)
    db = _FakeDb(_FakeSystem())
    event = ingest_event(
        db,
        "operator",
        {
            "ai_system_id": db.system.id,
            "source_kind": "otel",
            "tool_name": "cancel_order",
            "arguments": {"order_id": "ORD-1001"},
            "authorization_context": {"authorized": False},
            "occurred_at": datetime.now(UTC),
            "correlation_id": "lab-1",
            "labelled_synthetic": True,
        },
    )
    assert event.tool_name == "cancel_order"
    assert event.result_metadata["runtime_firewall"] is False
    assert event.result_metadata["enforcement"] == "none"
    assert recorded[0]["payload"]["runtime_firewall"] is False
    assert recorded[0]["payload"]["legal_compliance_claim"] is False
