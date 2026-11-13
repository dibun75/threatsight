from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from threatsight_api.analysis.rules import AnalysisStop, evaluate
from threatsight_api.analysis.vocabulary import RULESET_VERSION
from threatsight_api.graph.fixture import load_fixture
from threatsight_api.graph.project import content_hash, project

FORBIDDEN = ("safe", "secure", "compliant", "compromised", "exploitable", "breached", "protected", "reachable")


def _nordic():
    bundle = load_fixture("nordic-retail")
    built = project(
        bundle.records,
        now=datetime(2026, 10, 30, tzinfo=UTC),
        memberships=bundle.memberships,
        dependency_pairs=bundle.dependency_pairs,
        actor="fixture",
    )
    return built


def _run(built=None):
    built = built or _nordic()
    return evaluate(built.nodes, built.edges, built.conflicts, built.memberships)


def _one(outcome, rule_id, state=None):
    rows = [item for item in outcome["results"] if item["rule_id"] == rule_id and (state is None or item["state"] == state)]
    assert rows, rule_id
    return rows[0]


def test_nordic_analysis_is_deterministic_and_does_not_upgrade_evidence() -> None:
    built = _nordic()
    before = content_hash(built)
    first = _run(built)
    second = _run(built)
    assert content_hash(built) == before
    assert first == second
    assert first["ruleset_version"] == RULESET_VERSION
    assert json.dumps(first["results"]) == json.dumps(sorted(first["results"], key=lambda item: (item["category"], item["rule_id"], item["service_key"] or "", item["state"])))
    assert all(item["maturity"] != "live_verified" for item in first["results"])
    assert all(item["node_keys"] for item in first["results"])
    for item in first["results"]:
        text = f"{item['state']} {item['explanation']}"
        for word in FORBIDDEN:
            assert f" {word} " not in f" {text} "
        assert "<" not in item["explanation"]
        assert "attributes" not in item
        assert "payload" not in item


def test_nordic_fixture_covers_required_candidates_and_gaps() -> None:
    outcome = _run()
    entry = _one(outcome, "internet-entry-candidate-v1", "supported_candidate")
    assert "customer-ordering" in (entry["service_key"] or "")
    assert "manual" in entry["evidence_modes"]
    assert "not_packet_delivery" in entry["limitations"]
    missing = _one(outcome, "internet-join-unknown-v1", "unknown")
    assert "traversal_limit" in missing["limitations"]
    assert "depth_limit" in missing["limitations"]
    assert "missing_target" in _one(outcome, "gap-dangling-reference-v1", "unknown")["limitations"]
    direct = _one(outcome, "privileged-direct-assignment-v1", "supported_candidate")
    transitive = _one(outcome, "privileged-transitive-assignment-v1", "unknown")
    assert "direct_assignment" in direct["limitations"]
    assert "missing_group_assignment" in transitive["limitations"]
    assert direct["rule_id"] != transitive["rule_id"]
    remote = [item for item in outcome["results"] if item["rule_id"] == "cross-domain-service-v1" and "remote-access" in (item["service_key"] or "")]
    assert remote
    assert any("inferred" in item["evidence_modes"] for item in remote)
    truncated = [item for item in remote if "traversal_limit" in item["limitations"]]
    assert truncated
    assert all(item["state"] == "unknown" for item in truncated)
    assert any(item["state"] == "supported_candidate" for item in remote)
    management = _one(outcome, "management-configured-unknown-v1", "unknown")
    assert management["evidence_modes"] == ["configured"]
    assert "configured_is_not_observed" in management["limitations"]
    assert _one(outcome, "contradiction-configured-observed-v1", "conflicting")
    stale = _one(outcome, "gap-stale-input-v1", "unknown")
    assert stale["freshness"] == "stale"
    assert _one(outcome, "gap-dangling-reference-v1", "unknown")
    assert _one(outcome, "gap-unsupported-capability-v1", "unsupported")
    unresolved = _one(outcome, "cross-source-unresolved-v1", "conflicting")
    assert "not_merged" in unresolved["limitations"]


def test_partial_collection_stays_unknown() -> None:
    bundle = load_fixture("partial")
    built = project(bundle.records, now=datetime(2026, 10, 30, tzinfo=UTC), memberships=bundle.memberships, partial=True, actor="fixture")
    built.conflicts.append({"conflict_type": "partial_omission", "subject_key": "synthetic.fixture:omitted", "detail_code": "omitted_by_partial_collection"})
    outcome = evaluate(built.nodes, built.edges, built.conflicts, built.memberships)
    row = _one(outcome, "gap-partial-collection-v1", "unknown")
    assert "partial_collection" in row["limitations"]


def _node(key, node_type, **extra):
    item = {
        "source_key": key,
        "node_type": node_type,
        "evidence_mode": "configured",
        "freshness": "fresh",
        "maturity": "fixture_tested",
        "attributes": {},
    }
    item.update(extra)
    return item


def _edge(edge_type, left, right, mode="configured"):
    return {"source_key": f"{edge_type}|{left}|{right}", "edge_type": edge_type, "from_key": left, "to_key": right, "evidence_mode": mode, "maturity": "fixture_tested"}


def test_cycle_depth_fanout_and_inspection_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    address = _node("public", "public_address")
    service = _node("service", "business_service")
    other = _node("other", "device")
    cycle = evaluate(
        [address, service, other],
        [_edge("contains", "public", "other"), _edge("contains", "other", "public")],
        [],
        [{"service_key": "service", "member_key": "public", "role": "entry"}],
    )
    assert any("cycle_terminated" in item["limitations"] for item in cycle["results"])
    chain = [_node("public", "public_address")]
    edges = []
    previous = "public"
    for index in range(6):
        key = f"hop-{index}"
        chain.append(_node(key, "route" if index == 5 else "device"))
        edges.append(_edge("contains", previous, key))
        previous = key
    deep = evaluate(chain + [_node("service", "business_service")], edges, [], [{"service_key": "service", "member_key": "public", "role": "entry"}])
    limited = _one(deep, "internet-join-unknown-v1", "unknown")
    assert "depth_limit" in limited["limitations"]
    assert limited["state"] != "supported_candidate"
    wide_nodes = [_node("public", "public_address"), _node("service", "business_service")]
    wide_edges = []
    for index in range(25):
        wide_nodes.append(_node(f"leaf-{index}", "device"))
        wide_edges.append(_edge("contains", "public", f"leaf-{index}"))
    wide = evaluate(wide_nodes, wide_edges, [], [{"service_key": "service", "member_key": "public", "role": "entry"}])
    assert "fanout_limit" in _one(wide, "internet-join-unknown-v1")["limitations"]
    monkeypatch.setattr("threatsight_api.analysis.rules.MAX_INSPECTED", 1)
    inspected = evaluate(
        [_node("public", "public_address"), _node("service", "business_service"), _node("child", "device")],
        [_edge("contains", "public", "child")],
        [],
        [{"service_key": "service", "member_key": "public", "role": "entry"}],
    )
    assert "inspection_limit" in _one(inspected, "internet-join-unknown-v1")["limitations"]
    monkeypatch.setattr("threatsight_api.analysis.rules.MAX_PATHS", 1)
    monkeypatch.setattr("threatsight_api.analysis.rules.MAX_INSPECTED", 200)
    capped = evaluate(wide_nodes[:5], wide_edges[:3], [], [{"service_key": "service", "member_key": "public", "role": "entry"}])
    assert "path_limit" in _one(capped, "internet-join-unknown-v1")["limitations"]


def test_time_bound_does_not_publish_a_conclusion() -> None:
    with pytest.raises(AnalysisStop) as exc:
        evaluate([], [], [], [], elapsed=lambda: 9)
    assert exc.value.code == "bound_exceeded"


def test_malicious_label_is_not_copied_into_an_explanation() -> None:
    outcome = evaluate(
        [
            _node("public", "public_address", attributes={"name": "<script>alert(1)</script>"}),
            _node("service", "business_service", attributes={"name": "safe"}),
        ],
        [],
        [],
        [{"service_key": "service", "member_key": "public", "role": "entry"}],
    )
    for item in outcome["results"]:
        assert "<script>" not in item["explanation"]
        assert "safe" not in item["explanation"]
