from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threatsight_api.graph.bounds import MAX_DEGREE, MAX_NODES
from threatsight_api.graph.fixture import APP, AZURE, ENTRA, JUNOS, MERAKI, SQL, load_fixture
from threatsight_api.graph.project import content_hash, project
from threatsight_api.graph.sanitize import GraphFailure, plain_text
from threatsight_api.graph.vocabulary import EDGE_TYPES, NODE_TYPES, SITE_KEY_RULE, source_key

NOW = datetime(2026, 10, 30, tzinfo=UTC)
FORBIDDEN = ("exploitable", "compromised", "internet_exposed", "control_effective", "reachable", "vulnerable")


def _build(name: str = "nordic-retail"):
    bundle = load_fixture(name)
    return bundle, project(
        bundle.records,
        now=NOW,
        memberships=bundle.memberships,
        dependency_pairs=bundle.dependency_pairs,
        partial=bundle.partial,
        actor="fixture",
    )


def test_fixture_graph_is_typed_synthetic_and_not_a_finding() -> None:
    bundle, projected = _build()
    assert bundle.records
    assert {node["node_type"] for node in projected.nodes} <= set(NODE_TYPES)
    assert {edge["edge_type"] for edge in projected.edges} <= set(EDGE_TYPES)
    assert "RELATED_TO" not in {edge["edge_type"] for edge in projected.edges}
    services = [node for node in projected.nodes if node["node_type"] == "business_service"]
    assert len(services) == 3
    assert {node["maturity"] for node in services} == {"synthetic"}
    assert {node["evidence_mode"] for node in services} == {"manual"}
    nic = next(node for node in projected.nodes if node["vendor_id"].endswith("synth-nic"))
    assert nic["maturity"] == "fixture_tested"
    assert nic["maturity"] != "live_verified"
    blob = str(projected.content()).lower()
    for word in FORBIDDEN:
        assert word not in blob
    assert "not_an_exposure_finding" in projected.limitations
    assert "absence_is_not_negative_evidence" in projected.limitations


def test_repeated_projection_is_deterministic() -> None:
    _, first = _build()
    _, second = _build()
    assert content_hash(first) == content_hash(second)
    assert [node["source_key"] for node in first.nodes] == [node["source_key"] for node in second.nodes]


def test_names_and_addresses_do_not_merge_and_site_key_links_without_collapsing() -> None:
    _, projected = _build()
    shared = [node for node in projected.nodes if node["label"] == "shared-label"]
    assert len(shared) == 2
    assert shared[0]["source_key"] != shared[1]["source_key"]
    pair = {shared[0]["source_key"], shared[1]["source_key"]}
    assert not any({edge["from_key"], edge["to_key"]} == pair for edge in projected.edges)
    assert any(item["conflict_type"] == "ambiguous_identity" for item in projected.conflicts)
    assert any(item["conflict_type"] == "duplicate_address" for item in projected.conflicts)
    link = next(edge for edge in projected.edges if edge["derivation_rule"] == SITE_KEY_RULE)
    assert link["edge_type"] == "peers_with"
    assert link["evidence_mode"] == "inferred"
    assert link["evidence_mode"] != "observed"
    assert link["derivation_version"] == "1"
    assert link["confidence"] == "derived"
    assert "not_an_exposure_finding" in link["limitations"]
    assert len(link["contributing"]) == 2
    assert all(any(node["source_key"] == key for node in projected.nodes) for key in link["contributing"])


def test_conflicts_stale_dangling_and_unsupported_are_preserved() -> None:
    _, projected = _build()
    interface = next(node for node in projected.nodes if node["vendor_id"] == "iface:ge-0/0/0")
    assert interface["lifecycle"] == "conflicting"
    assert interface["attributes"]["admin_status"] == "up"
    assert interface["attributes"]["oper_status"] == "down"
    assert any(item["conflict_type"] == "configured_observed" for item in projected.conflicts)
    route = next(node for node in projected.nodes if node["vendor_id"] == "route:default")
    assert route["freshness"] == "stale"
    assert route["lifecycle"] == "stale"
    assert any(item["conflict_type"] == "dangling_reference" and item["detail_code"] == "missing_reference" for item in projected.conflicts)
    assert any(item["conflict_type"] == "unsupported" for item in projected.conflicts)
    assert not any(node["node_type"] == "routing_instance" for node in projected.nodes)
    dependency = next(edge for edge in projected.edges if edge["derivation_rule"] == "fixture-service-dependency-v1")
    assert dependency["from_key"] == source_key(AZURE, APP)
    assert dependency["to_key"] == source_key(AZURE, SQL)
    assert any(edge["edge_type"] == "member_of" and edge["connector_key"] == ENTRA for edge in projected.edges)
    assert any(edge["edge_type"] == "assigned_to" for edge in projected.edges)
    assert any(node["connector_key"] == MERAKI for node in projected.nodes)
    assert any(node["connector_key"] == JUNOS and node["node_type"] == "software_version" for node in projected.nodes)


def test_malicious_labels_controls_and_verdict_fields_are_rejected() -> None:
    bundle = load_fixture("nordic-retail")
    record = dict(bundle.records[0])
    record["attributes"] = {"name": "edge\nINJECTED <script>", "exposed": "true", "verdict": "compromised"}
    projected = project([record], now=NOW)
    assert "\n" not in projected.nodes[0]["label"]
    assert "\n" not in plain_text("edge\nINJECTED <script>")
    assert "<" not in plain_text("edge\nINJECTED <script>")
    assert "<" not in projected.nodes[0]["label"]
    assert "exposed" not in projected.nodes[0]["attributes"]
    assert "verdict" not in projected.nodes[0]["attributes"]
    poisoned = dict(bundle.records[0])
    poisoned["external_id"] = "bad\nid"
    with pytest.raises(GraphFailure) as caught:
        project([poisoned], now=NOW)
    assert caught.value.code == "source_rejected"


def test_unknown_vocabulary_and_bounds_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    projected = project([{
        "connector_key": "azure.resource_graph",
        "contract": "custom.v1",
        "external_id": "custom:1",
        "kind": "exploit_path",
        "truth_state": "observed",
        "collected_at": NOW,
        "attributes": {"name": "nope"},
        "envelope_maturity": "fixture_tested",
        "envelope_mode": "fixture",
    }], now=NOW)
    assert projected.nodes == []
    assert projected.conflicts[0]["conflict_type"] == "unsupported"
    records = [{
        "connector_key": "azure.resource_graph",
        "contract": "device.v1",
        "external_id": f"device:{index}",
        "kind": "device",
        "truth_state": "observed",
        "collected_at": NOW,
        "attributes": {"name": "n"},
        "envelope_maturity": "fixture_tested",
        "envelope_mode": "fixture",
    } for index in range(MAX_NODES + 1)]
    with pytest.raises(GraphFailure) as caught:
        project(records, now=NOW)
    assert caught.value.code == "bound_exceeded"
    monkeypatch.setattr("threatsight_api.graph.project.MAX_DEGREE", 1)
    _, capped = _build()
    assert "degree_capped" in capped.limitations
    assert MAX_DEGREE >= 1
