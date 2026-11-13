"""Fixed analysis rules. Clients cannot supply rule code or traversal expressions."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from threatsight_api.analysis.bounds import (
    MAX_DEPTH,
    MAX_EXPLANATION,
    MAX_FANOUT,
    MAX_INSPECTED,
    MAX_PATHS,
    MAX_RESULTS,
    MAX_SECONDS,
)
from threatsight_api.analysis.vocabulary import GLOBAL_LIMITATIONS, RULESET_VERSION
from threatsight_api.config import get_settings
from threatsight_api.graph.sanitize import plain_text

RULES: tuple[dict, ...] = (
    {
        "rule_id": "internet-entry-candidate-v1",
        "version": "1",
        "category": "internet_exposure_candidate",
        "evidence": ("manual", "configured", "observed", "inferred"),
        "depth": MAX_DEPTH,
        "stop": "unknown when no public entry membership exists",
        "explanation": "A business service has a manual entry membership to a public-address record.",
    },
    {
        "rule_id": "internet-join-unknown-v1",
        "version": "1",
        "category": "internet_exposure_candidate",
        "evidence": ("configured", "observed"),
        "depth": MAX_DEPTH,
        "stop": "unknown when no route or policy fact joins the entry to the application",
        "explanation": "The public entry and application dependency are not joined by a route or policy fact.",
    },
    {
        "rule_id": "management-configured-unknown-v1",
        "version": "1",
        "category": "management_plane_candidate",
        "evidence": ("configured",),
        "depth": 2,
        "stop": "unknown unless an observed management fact exists",
        "explanation": "A management interface or service is configured. No observed operational fact is present.",
    },
    {
        "rule_id": "privileged-direct-assignment-v1",
        "version": "1",
        "category": "privileged_identity_path",
        "evidence": ("configured", "manual"),
        "depth": 3,
        "stop": "unknown when the assignment does not name an identity and a role",
        "explanation": "A role assignment record points directly at an identity and a role.",
    },
    {
        "rule_id": "privileged-transitive-assignment-v1",
        "version": "1",
        "category": "privileged_identity_path",
        "evidence": ("configured", "inferred"),
        "depth": 4,
        "stop": "unknown when group membership is not backed by an assignment on that group",
        "explanation": "Group membership without an assignment on that group is not a direct privilege path.",
    },
    {
        "rule_id": "cross-domain-service-v1",
        "version": "1",
        "category": "cross_domain_service_path",
        "evidence": ("manual", "configured", "observed", "inferred"),
        "depth": MAX_DEPTH,
        "stop": "unknown when the service has no network or VPN membership",
        "explanation": "A business service lists network or VPN dependencies across connectors. Inferred links stay inferred.",
    },
    {
        "rule_id": "cross-source-unresolved-v1",
        "version": "1",
        "category": "cross_domain_service_path",
        "evidence": ("configured", "observed"),
        "depth": 1,
        "stop": "conflicting when identity is ambiguous; records stay separate",
        "explanation": "Two sources share a label or address and no deterministic rule merged them.",
    },
    {
        "rule_id": "contradiction-configured-observed-v1",
        "version": "1",
        "category": "contradiction_gap",
        "evidence": ("configured", "observed"),
        "depth": 1,
        "stop": "conflicting when admin and operational status differ",
        "explanation": "One source record contains both a configured state and a different operational state.",
    },
    {
        "rule_id": "gap-stale-input-v1",
        "version": "1",
        "category": "contradiction_gap",
        "evidence": ("observed", "configured"),
        "depth": 1,
        "stop": "unknown when the collection time is stale",
        "explanation": "A contributing record is stale. The analysis does not treat it as current.",
    },
    {
        "rule_id": "gap-dangling-reference-v1",
        "version": "1",
        "category": "contradiction_gap",
        "evidence": ("configured",),
        "depth": 1,
        "stop": "unknown when a source id has no target",
        "explanation": "A source record points at an identifier that is not in the snapshot.",
    },
    {
        "rule_id": "gap-unsupported-capability-v1",
        "version": "1",
        "category": "contradiction_gap",
        "evidence": ("configured",),
        "depth": 1,
        "stop": "unsupported when the connector reported an unmapped capability",
        "explanation": "The connector reported an unsupported or unmapped capability.",
    },
    {
        "rule_id": "gap-partial-collection-v1",
        "version": "1",
        "category": "contradiction_gap",
        "evidence": ("configured", "observed"),
        "depth": 1,
        "stop": "unknown when a later collection omitted a prior record",
        "explanation": "A later partial collection omitted a previously seen source key.",
    },
)


class AnalysisStop(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def evaluate(
    nodes: list[dict],
    edges: list[dict],
    conflicts: list[dict],
    memberships: list[dict],
    *,
    elapsed: Callable[[], float] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> dict:
    if cancelled and cancelled():
        raise AnalysisStop("cancelled")
    spent = elapsed or (lambda: 0.0)
    if spent() > MAX_SECONDS:
        raise AnalysisStop("bound_exceeded")
    graph = _index(nodes, edges)
    limits = _Limits()
    results: list[dict] = []
    results.extend(_internet(graph, memberships, limits, elapsed=spent, cancelled=cancelled))
    results.extend(_management(graph, conflicts, limits))
    results.extend(_privilege(graph, memberships, limits))
    results.extend(_cross_domain(graph, memberships, conflicts, limits, elapsed=spent, cancelled=cancelled))
    results.extend(_gaps(graph, conflicts, limits))
    results = results[:MAX_RESULTS]
    results.sort(key=lambda item: (item["category"], item["rule_id"], item["service_key"] or "", item["state"]))
    return {
        "ruleset_version": RULESET_VERSION,
        "results": results,
        "limitations": sorted(set([*GLOBAL_LIMITATIONS, *limits.reasons])),
    }


def _index(nodes: list[dict], edges: list[dict]) -> dict:
    by_key = {node["source_key"]: node for node in nodes}
    outgoing: dict[str, list[dict]] = defaultdict(list)
    incoming: dict[str, list[dict]] = defaultdict(list)
    for edge in edges:
        outgoing[edge["from_key"]].append(edge)
        incoming[edge["to_key"]].append(edge)
    for bucket in (outgoing, incoming):
        for key in bucket:
            bucket[key].sort(key=lambda item: (item["edge_type"], item["source_key"]))
    return {"nodes": by_key, "outgoing": outgoing, "incoming": incoming, "edges": list(edges)}


class _Limits:
    def __init__(self) -> None:
        self.inspected = 0
        self.truncated = False
        self.reasons: list[str] = []

    def inspect(self) -> bool:
        self.inspected += 1
        if self.inspected > MAX_INSPECTED:
            self.truncated = True
            self.reasons.append("inspection_limit")
            return False
        return True


def _search(graph: dict, start: str, edge_types: frozenset[str], limits: _Limits, *, elapsed: Callable[[], float] | None = None, cancelled: Callable[[], bool] | None = None) -> dict:
    seen = {start}
    queue = [(start, 0, (start,))]
    nodes: list[str] = []
    edges: list[str] = []
    types: set[str] = set()
    modes: set[str] = set()
    reasons: list[str] = []
    truncated = False
    spent = elapsed or (lambda: 0.0)
    while queue:
        if cancelled and cancelled():
            raise AnalysisStop("cancelled")
        if spent() > MAX_SECONDS:
            raise AnalysisStop("bound_exceeded")
        if get_settings().kill_switch:
            raise AnalysisStop("kill_switch")
        if not limits.inspect():
            truncated = True
            reasons.append("inspection_limit")
            break
        key, depth, path = queue.pop(0)
        node = graph["nodes"].get(key)
        if node is not None:
            nodes.append(key)
            types.add(node["node_type"])
        neighbors = [
            edge for edge in graph["outgoing"].get(key, []) + graph["incoming"].get(key, [])
            if edge["edge_type"] in edge_types
        ]
        neighbors.sort(key=lambda item: (item["edge_type"], item["source_key"]))
        if depth >= MAX_DEPTH:
            blocked = False
            for edge in neighbors:
                other = edge["to_key"] if edge["from_key"] == key else edge["from_key"]
                if other in path:
                    reasons.append("cycle_terminated")
                elif other not in seen:
                    blocked = True
            if blocked:
                truncated = True
                reasons.append("depth_limit")
            continue
        if len(neighbors) > MAX_FANOUT:
            truncated = True
            reasons.append("fanout_limit")
            neighbors = neighbors[:MAX_FANOUT]
        for edge in neighbors:
            other = edge["to_key"] if edge["from_key"] == key else edge["from_key"]
            if other in path:
                reasons.append("cycle_terminated")
                continue
            modes.add(edge["evidence_mode"])
            if other in seen:
                continue
            if len(edges) >= MAX_PATHS:
                reasons.append("path_limit")
            else:
                edges.append(edge["source_key"])
            seen.add(other)
            queue.append((other, depth + 1, (*path, other)))
    if truncated:
        limits.truncated = True
        limits.reasons.extend(reasons)
    else:
        limits.reasons.extend(item for item in reasons if item == "cycle_terminated")
    return {"nodes": nodes[:MAX_PATHS], "edges": edges[:MAX_PATHS], "types": types, "modes": modes, "truncated": truncated, "reasons": reasons}


def _internet(graph, memberships, limits: _Limits, *, elapsed=None, cancelled=None) -> list[dict]:
    found = []
    for item in memberships:
        if item["role"] != "entry":
            continue
        member = graph["nodes"].get(item["member_key"])
        service = graph["nodes"].get(item["service_key"])
        if member is None or service is None or member["node_type"] != "public_address":
            continue
        found.append(_result(
            "internet_exposure_candidate", "supported_candidate", "internet-entry-candidate-v1", "1",
            item["service_key"],
            "A business service has a manual entry membership to a public-address record. This is not packet delivery.",
            ["manual", member["evidence_mode"]], _maturity(member), member["freshness"],
            ["missing_route_or_policy"], [member["source_key"], service["source_key"]],
            [member["source_key"], service["source_key"]], [],
        ))
        joined = _search(graph, member["source_key"], frozenset({"contains", "attached_to", "depends_on", "routes_to", "in_zone", "permits_reference", "denies_reference"}), limits, elapsed=elapsed, cancelled=cancelled)
        if "route" in joined["types"] or "security_policy" in joined["types"]:
            continue
        if joined["truncated"]:
            found.append(_result(
                "internet_exposure_candidate", "unknown", "internet-join-unknown-v1", "1",
                item["service_key"],
                "The bounded walk stopped before a route or policy fact could be confirmed or excluded.",
                [member["evidence_mode"]], _maturity(member), member["freshness"],
                ["traversal_limit", *joined["reasons"]], [member["source_key"]],
                joined["nodes"] or [member["source_key"]], joined["edges"],
            ))
        else:
            found.append(_result(
                "internet_exposure_candidate", "unknown", "internet-join-unknown-v1", "1",
                item["service_key"],
                "No route or policy fact joins the public-address record to an application dependency.",
                [member["evidence_mode"]], _maturity(member), member["freshness"],
                ["missing_route", "missing_policy", *joined["reasons"]], [member["source_key"]],
                joined["nodes"] or [member["source_key"]], joined["edges"],
            ))
    return found


def _management(graph, conflicts, limits: _Limits) -> list[dict]:
    _ = limits
    results = []
    for node in graph["nodes"].values():
        name = str(node.get("attributes", {}).get("name") or "")
        if node["node_type"] != "network_interface" or name != "fxp0":
            continue
        observed = node["evidence_mode"] == "observed"
        results.append(_result(
            "management_plane_candidate", "unknown" if not observed else "supported_candidate",
            "management-configured-unknown-v1", "1", None,
            "A management interface is present with configured evidence. Operational state was not observed.",
            [node["evidence_mode"]], _maturity(node), node["freshness"],
            ["configured_is_not_observed"], [node["source_key"]],
            [node["source_key"]], [],
        ))
    for item in conflicts:
        if item["conflict_type"] != "unsupported" or item["detail_code"] != "configuration_is_not_reachability":
            continue
        results.append(_result(
            "management_plane_candidate", "unsupported", "management-configured-unknown-v1", "1", None,
            "The connector recorded a management service as configuration only. Operational state was not observed.",
            ["configured"], "fixture_tested", "untested",
            ["configured_is_not_observed"], [item["subject_key"]],
            [item["subject_key"]], [],
        ))
    return results


def _privilege(graph, memberships, limits: _Limits) -> list[dict]:
    _ = limits
    results = []
    assignments = [node for node in graph["nodes"].values() if node["node_type"] == "role_assignment"]
    for assignment in assignments:
        targets = [edge for edge in graph["outgoing"].get(assignment["source_key"], []) if edge["edge_type"] == "assigned_to"]
        target_nodes = [graph["nodes"].get(edge["to_key"]) for edge in targets]
        kinds = {node["node_type"] for node in target_nodes if node}
        if "identity" in kinds and "role" in kinds:
            identity = next(node for node in target_nodes if node and node["node_type"] == "identity")
            results.append(_result(
                "privileged_identity_path", "supported_candidate", "privileged-direct-assignment-v1", "1",
                _service_for(memberships, "administration"),
                "The role assignment names the identity directly. This does not prove the privilege is effective.",
                ["configured", "manual"], _maturity(assignment), assignment["freshness"],
                ["direct_assignment", "not_effective_privilege"],
                [assignment["source_key"], identity["source_key"]],
                [assignment["source_key"], identity["source_key"]],
                [edge["source_key"] for edge in targets],
            ))
    groups = {edge["to_key"] for edge in graph["edges"] if edge["edge_type"] == "member_of"}
    assigned_groups = set()
    for assignment in assignments:
        for edge in graph["outgoing"].get(assignment["source_key"], []):
            if edge["edge_type"] == "assigned_to":
                assigned_groups.add(edge["to_key"])
    if groups and not groups & assigned_groups:
        results.append(_result(
            "privileged_identity_path", "unknown", "privileged-transitive-assignment-v1", "1",
            _service_for(memberships, "administration"),
            "A group membership exists. No role assignment names that group, so this is not a transitive privilege path.",
            ["configured"], "fixture_tested", "fresh",
            ["transitive_not_direct", "missing_group_assignment"], sorted(groups),
            sorted(groups), [],
        ))
    return results


def _cross_domain(graph, memberships, conflicts, limits: _Limits, *, elapsed=None, cancelled=None) -> list[dict]:
    results = []
    for item in memberships:
        if item["role"] != "network":
            continue
        member = graph["nodes"].get(item["member_key"])
        if member is None or member["node_type"] not in {"vpn", "network", "security_zone"}:
            continue
        found = _search(graph, member["source_key"], frozenset({"contains", "attached_to", "peers_with", "in_zone"}), limits, elapsed=elapsed, cancelled=cancelled)
        modes = {member["evidence_mode"], "manual", *found["modes"]}
        extra = ["inferred_not_observed"] if "inferred" in modes else []
        if found["truncated"]:
            extra.append("traversal_limit")
        results.append(_result(
            "cross_domain_service_path",
            "unknown" if found["truncated"] else "supported_candidate",
            "cross-domain-service-v1", "1",
            item["service_key"],
            "The bounded walk stopped before the rest of the network neighborhood could be used." if found["truncated"] else "The service membership includes a network or VPN record. Inferred edges remain inferred and are weaker than observed facts.",
            sorted(modes), _maturity(member), member["freshness"],
            [*extra, *found["reasons"]],
            [member["source_key"], item["service_key"]],
            [member["source_key"], item["service_key"], *found["nodes"]][:MAX_PATHS],
            found["edges"],
        ))
    for conflict in conflicts:
        if conflict["conflict_type"] in {"ambiguous_identity", "duplicate_address"}:
            results.append(_result(
                "cross_domain_service_path", "conflicting", "cross-source-unresolved-v1", "1", None,
                "Shared label or address text did not merge the records. No path was created between them.",
                ["configured"], "fixture_tested", "fresh",
                ["not_merged"], [conflict["subject_key"]],
                [conflict["subject_key"]], [],
            ))
    return results


def _gaps(graph, conflicts, limits: _Limits) -> list[dict]:
    _ = (graph, limits)
    mapping = {
        "configured_observed": ("conflicting", "contradiction-configured-observed-v1", "gap-configured-observed"),
        "stale_source": ("unknown", "gap-stale-input-v1", "stale_input"),
        "dangling_reference": ("unknown", "gap-dangling-reference-v1", "missing_target"),
        "unsupported": ("unsupported", "gap-unsupported-capability-v1", "unsupported_capability"),
        "partial_omission": ("unknown", "gap-partial-collection-v1", "partial_collection"),
    }
    results = []
    for conflict in conflicts:
        choice = mapping.get(conflict["conflict_type"])
        if choice is None:
            continue
        state, rule_id, limitation = choice
        freshness = "stale" if conflict["conflict_type"] == "stale_source" else "untested"
        results.append(_result(
            "contradiction_gap", state, rule_id, "1", None,
            _gap_text(conflict["conflict_type"]),
            ["configured", "observed"] if conflict["conflict_type"] == "configured_observed" else ["configured"],
            "fixture_tested", freshness, [limitation], [conflict["subject_key"]],
            [conflict["subject_key"]], [],
        ))
    return results


def _gap_text(kind: str) -> str:
    return {
        "configured_observed": "Configured and operational values differ on one record. Neither value was discarded.",
        "stale_source": "The collection time is outside the freshness window.",
        "dangling_reference": "A referenced source identifier is absent from the snapshot.",
        "unsupported": "The connector marked a capability unsupported.",
        "partial_omission": "A later partial collection omitted this source key. The record was not deleted.",
    }[kind]


def _service_for(memberships, role: str) -> str | None:
    for item in memberships:
        if item["role"] == role:
            return item["service_key"]
    return None


def _maturity(node: dict) -> str:
    value = node.get("maturity") or "fixture_tested"
    if value == "live_verified":
        return "live_verified"
    if value == "synthetic":
        return "synthetic"
    return "fixture_tested"


def _result(category, state, rule_id, version, service_key, explanation, modes, maturity, freshness, limitations, missing, nodes, edges) -> dict:
    return {
        "category": category,
        "state": state,
        "rule_id": rule_id,
        "rule_version": version,
        "service_key": service_key,
        "explanation": plain_text(explanation)[:MAX_EXPLANATION],
        "evidence_modes": sorted(set(modes)),
        "maturity": maturity if maturity in {"synthetic", "fixture_tested", "live_verified"} else "fixture_tested",
        "freshness": freshness if freshness in {"fresh", "stale", "untested"} else "untested",
        "limitations": sorted(set([*GLOBAL_LIMITATIONS, *limitations])),
        "missing_facts": sorted(set(missing)),
        "node_keys": nodes[:MAX_PATHS],
        "edge_keys": edges[:MAX_PATHS],
    }
