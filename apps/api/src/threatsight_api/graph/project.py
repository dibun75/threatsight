"""Deterministic projection from normalized records to a graph snapshot.

The projector describes source assertions and explicit relationships.
It does not decide exposure, reachability, control effectiveness, or compromise.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from threatsight_api.graph.bounds import MAX_CONFLICTS, MAX_DEGREE, MAX_EDGES, MAX_NODES, MAX_OBSERVATIONS
from threatsight_api.graph.sanitize import GraphFailure, clean_attributes, clean_label, require_identifier
from threatsight_api.graph.vocabulary import (
    ABSENCE_IS_NOT_EVIDENCE,
    ADDRESS_RULE,
    ARM_RULE,
    ASSIGNMENT_RULE,
    CONFLICT_TYPES,
    DEPENDENCY_RULE,
    EDGE_TYPES,
    GROUP_RULE,
    KIND_NODE,
    NOT_A_FINDING,
    NOT_CONTROL,
    NOT_REACHABILITY,
    PARENT_RULE,
    POLICY_RULE,
    SITE_KEY_RULE,
    SITE_KEY_VERSION,
    SOFTWARE_RULE,
    UNMAPPED_KINDS,
    source_key,
)

_SITE_KEY = re.compile(r"^synth-site-[a-z0-9-]{1,40}$")
_DOCUMENTED_PREFIXES = ("203.0.113.", "198.51.100.")
_FRESH_DAYS = 30


@dataclass
class Projection:
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    conflicts: list[dict] = field(default_factory=list)
    memberships: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    partial: bool = False

    def content(self) -> dict:
        return {
            "conflicts": [_public(item) for item in self.conflicts],
            "edges": [_public(item) for item in self.edges],
            "limitations": sorted(set(self.limitations)),
            "memberships": [_public(item) for item in self.memberships],
            "nodes": [_public(item) for item in self.nodes],
            "observations": [_public(item) for item in self.observations],
        }


def _public(item: dict) -> dict:
    hidden = {"materialized_at", "scoped_at"}
    return {key: value for key, value in item.items() if key not in hidden}


def content_hash(projection: Projection) -> str:
    body = json.dumps(projection.content(), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def project(
    records: list[dict],
    *,
    now: datetime,
    memberships: list[tuple[str, str, str]] | None = None,
    dependency_pairs: list[tuple[str, str]] | None = None,
    partial: bool = False,
    actor: str = "fixture",
) -> Projection:
    if len(records) > MAX_NODES:
        raise GraphFailure("bound_exceeded")
    clock = now if now.tzinfo else now.replace(tzinfo=UTC)
    built = Projection(partial=partial)
    built.limitations.extend([NOT_A_FINDING, ABSENCE_IS_NOT_EVIDENCE])
    by_key: dict[str, dict] = {}
    deferred: list[dict] = []
    ordered = sorted(records, key=_record_sort)
    for record in ordered:
        if str(record.get("kind") or "") in {"group_membership", "device_status"}:
            deferred.append(record)
            continue
        _consume(built, by_key, record, clock)
        if len(built.nodes) > MAX_NODES or len(built.observations) > MAX_OBSERVATIONS:
            raise GraphFailure("bound_exceeded")
    for record in deferred:
        _deferred(built, by_key, record, clock)
    _derive(built, by_key, dependency_pairs or [])
    _memberships(built, by_key, memberships or [], actor, clock)
    _ambiguity(built, by_key)
    if len(built.edges) > MAX_EDGES or len(built.conflicts) > MAX_CONFLICTS:
        raise GraphFailure("bound_exceeded")
    built.nodes.sort(key=lambda item: (item["node_type"], item["source_key"]))
    built.edges.sort(key=lambda item: (item["edge_type"], item["source_key"]))
    built.conflicts.sort(key=lambda item: (item["conflict_type"], item["subject_key"], item["detail_code"]))
    built.observations.sort(key=lambda item: (item["subject_key"], item["evidence_mode"], item["source_record_id"]))
    built.memberships.sort(key=lambda item: (item["service_key"], item["member_key"], item["role"]))
    built.limitations = sorted(set(built.limitations))
    return built


def _record_sort(record: dict) -> tuple:
    return (
        str(record.get("connector_key") or ""),
        str(record.get("external_id") or ""),
        str(record.get("collected_at") or ""),
        str(record.get("kind") or ""),
    )


def _consume(built: Projection, by_key: dict[str, dict], record: dict, now: datetime) -> None:
    connector = require_identifier(record.get("connector_key"), max_len=64)
    external_id = require_identifier(record.get("external_id"))
    kind = require_identifier(record.get("kind"), max_len=64)
    truth = str(record.get("truth_state") or "unknown")
    attributes, dropped = clean_attributes(record.get("attributes") or {})
    contract = require_identifier(record.get("contract") or "unspecified", max_len=80)
    collected = _collected(record.get("collected_at"), now)
    key = source_key(connector, external_id)
    maturity = _maturity(truth, str(record.get("envelope_maturity") or "fixture_tested"), str(record.get("envelope_mode") or "fixture"))
    evidence = _evidence(truth)
    freshness = "stale" if truth == "stale" or collected < now - timedelta(days=_FRESH_DAYS) else "fresh"
    lifecycle = "conflicting" if truth == "conflicting" else "stale" if freshness == "stale" or truth == "stale" else "active"
    limitations = _limitations(record.get("limitations"), dropped)
    if truth == "unsupported" or kind in {"collection_gap", "capability", "routing_instance"}:
        _conflict(built, key, "unsupported", "unmapped_or_unsupported")
        return
    if kind == "collection_status" or truth == "partial":
        built.partial = True
        built.limitations.append("partial_collection")
        return
    if kind == "management_service":
        _conflict(built, key, "unsupported", "configuration_is_not_reachability")
        return
    node_type = _node_type(kind, attributes)
    if node_type is None:
        _conflict(built, key, "unsupported", "unmapped_kind")
        return
    if _admin_oper_conflict(attributes):
        lifecycle = "conflicting"
        limitations.append("configured_observed")
        _conflict(built, key, "configured_observed", "admin_oper_differ")
    _observe(built, key, connector, contract, external_id, evidence, maturity, collected, now, attributes)
    existing = by_key.get(key)
    if existing is not None:
        if existing["attributes"] != attributes or existing["evidence_mode"] != evidence:
            existing["lifecycle"] = "conflicting"
            existing["limitations"] = sorted(set([*existing["limitations"], "conflicting_assertion"]))
            _conflict(built, key, "conflicting_assertion", "sources_disagree")
        return
    node = {
        "source_key": key,
        "node_type": node_type,
        "vendor_id": external_id,
        "label": clean_label(attributes.get("display_name") or attributes.get("name") or external_id),
        "maturity": maturity,
        "evidence_mode": evidence,
        "connector_key": connector,
        "source_contract": contract,
        "source_record_id": external_id,
        "collected_at": collected,
        "materialized_at": now,
        "freshness": freshness,
        "confidence": "stated" if evidence in {"observed", "configured", "manual"} else "derived",
        "limitations": sorted(set(limitations)),
        "lifecycle": lifecycle,
        "attributes": attributes,
    }
    if freshness == "stale":
        node["limitations"] = sorted(set([*node["limitations"], "stale_source"]))
        _conflict(built, key, "stale_source", "collection_aged")
    built.nodes.append(node)
    by_key[key] = node
    _derived_children(built, by_key, node, collected, now)


def _derived_children(built: Projection, by_key: dict[str, dict], node: dict, collected: datetime, now: datetime) -> None:
    address = str(node["attributes"].get("address") or "")
    if node["node_type"] != "public_address" and address.startswith(_DOCUMENTED_PREFIXES):
        child_key = f"{node['source_key']}:address"
        if child_key not in by_key:
            child = _derived_node(
                built, child_key, "public_address", address, node, collected, now, ADDRESS_RULE,
                {"address": clean_label(address), "address_is_not_exposure": "true"},
            )
            by_key[child_key] = child
        _edge(built, "attached_to", child_key, node["source_key"], node, ADDRESS_RULE, [node["source_key"], child_key])
    version = str(node["attributes"].get("software_version") or "")
    if version and node["node_type"] == "device":
        child_key = f"{node['source_key']}:software"
        if child_key not in by_key:
            child = _derived_node(
                built, child_key, "software_version", version, node, collected, now, SOFTWARE_RULE,
                {"version": clean_label(version)},
            )
            by_key[child_key] = child
        _edge(built, "sourced_from", child_key, node["source_key"], node, SOFTWARE_RULE, [node["source_key"]])


def _derived_node(built, key, node_type, label, parent, collected, now, rule, attributes) -> dict:
    node = {
        "source_key": key,
        "node_type": node_type,
        "vendor_id": key,
        "label": clean_label(label),
        "maturity": parent["maturity"],
        "evidence_mode": "inferred",
        "connector_key": parent["connector_key"],
        "source_contract": parent["source_contract"],
        "source_record_id": parent["source_record_id"],
        "collected_at": collected,
        "materialized_at": now,
        "freshness": parent["freshness"],
        "confidence": "derived",
        "limitations": sorted({NOT_A_FINDING, rule}),
        "lifecycle": parent["lifecycle"],
        "attributes": attributes,
        "derivation_rule": rule,
        "derivation_version": "1",
    }
    built.nodes.append(node)
    return node


def _deferred(built: Projection, by_key: dict[str, dict], record: dict, now: datetime) -> None:
    connector = require_identifier(record.get("connector_key"), max_len=64)
    kind = str(record.get("kind") or "")
    attributes, _dropped = clean_attributes(record.get("attributes") or {})
    collected = _collected(record.get("collected_at"), now)
    maturity = _maturity(str(record.get("truth_state") or ""), str(record.get("envelope_maturity") or "fixture_tested"), str(record.get("envelope_mode") or "fixture"))
    if kind == "group_membership":
        _group_edge(built, by_key, connector, attributes, collected, now, maturity)
        return
    external_id = require_identifier(record.get("external_id"))
    device = next((node for node in by_key.values() if node["vendor_id"] == external_id and node["connector_key"] == connector), None)
    key = device["source_key"] if device else source_key(connector, external_id)
    if device is None:
        _conflict(built, key, "dangling_reference", "missing_status_target")
    _observe(
        built, key, connector, require_identifier(record.get("contract") or "unspecified", max_len=80),
        external_id, _evidence(str(record.get("truth_state") or "")), maturity, collected, now, attributes,
    )


def _derive(built: Projection, by_key: dict[str, dict], dependency_pairs: list[tuple[str, str]]) -> None:
    nodes = list(by_key.values())
    vendor = {(node["connector_key"], node["vendor_id"]): node for node in nodes}
    for node in nodes:
        parent_id = str(node["attributes"].get("associated_resource_id") or "")
        if parent_id:
            parent = vendor.get((node["connector_key"], parent_id))
            if parent is None:
                _conflict(built, node["source_key"], "dangling_reference", "missing_parent")
            else:
                _parent_edge(built, parent, node)
        for reference in node["attributes"].get("reference_ids") or []:
            target = vendor.get((node["connector_key"], str(reference)))
            if target is None:
                _conflict(built, node["source_key"], "dangling_reference", "missing_reference")
                continue
            edge_type = "permits_reference" if node["attributes"].get("action") == "allow" else "denies_reference"
            if node["attributes"].get("action") not in {"allow", "deny"}:
                _conflict(built, node["source_key"], "dangling_reference", "missing_reference")
                continue
            _edge(built, edge_type, node["source_key"], target["source_key"], node, POLICY_RULE, [node["source_key"], target["source_key"]], extra=[NOT_CONTROL])
        principal = vendor.get((node["connector_key"], str(node["attributes"].get("principal_id") or "")))
        role = vendor.get((node["connector_key"], str(node["attributes"].get("role_id") or "")))
        if node["node_type"] == "role_assignment":
            if principal is None or role is None:
                _conflict(built, node["source_key"], "dangling_reference", "missing_assignment_target")
            if principal is not None:
                _edge(built, "assigned_to", node["source_key"], principal["source_key"], node, ASSIGNMENT_RULE, [node["source_key"], principal["source_key"]])
            if role is not None:
                _edge(built, "assigned_to", node["source_key"], role["source_key"], node, ASSIGNMENT_RULE, [node["source_key"], role["source_key"]])
    _site_links(built, nodes)
    _arm_links(built, nodes)
    for left, right in dependency_pairs:
        if left in by_key and right in by_key and left != right:
            _edge(built, "depends_on", left, right, by_key[left], DEPENDENCY_RULE, [left, right])
    _cap_degree(built)


def _parent_edge(built: Projection, parent: dict, child: dict) -> None:
    if parent["node_type"] == "security_zone":
        edge_type = "in_zone"
        source, target = child["source_key"], parent["source_key"]
    elif child["node_type"] == "route":
        edge_type = "routes_to"
        source, target = child["source_key"], parent["source_key"]
    elif parent["node_type"] in {"network_interface", "device"} and child["node_type"] in {"network_interface", "logical_interface"}:
        edge_type = "attached_to"
        source, target = child["source_key"], parent["source_key"]
    elif parent["node_type"] == "network" and child["node_type"] == "subnet":
        edge_type = "contains"
        source, target = parent["source_key"], child["source_key"]
    else:
        edge_type = "contains"
        source, target = parent["source_key"], child["source_key"]
    _edge(built, edge_type, source, target, child, PARENT_RULE, [parent["source_key"], child["source_key"]])


def _site_links(built: Projection, nodes: list[dict]) -> None:
    grouped: dict[str, list[dict]] = {}
    for node in nodes:
        site = str(node["attributes"].get("site_key") or "")
        if _SITE_KEY.fullmatch(site):
            grouped.setdefault(site, []).append(node)
    for site, members in grouped.items():
        ordered = sorted(members, key=lambda item: item["source_key"])
        for index, left in enumerate(ordered):
            for right in ordered[index + 1:]:
                if left["connector_key"] == right["connector_key"]:
                    continue
                _edge(built, "peers_with", left["source_key"], right["source_key"], left, SITE_KEY_RULE, [left["source_key"], right["source_key"]])
                _ = site


def _arm_links(built: Projection, nodes: list[dict]) -> None:
    armed = [node for node in nodes if str(node["vendor_id"]).startswith("/subscriptions/")]
    for parent in armed:
        prefix = parent["vendor_id"].rstrip("/") + "/"
        for child in armed:
            if child["source_key"] == parent["source_key"]:
                continue
            if str(child["vendor_id"]).startswith(prefix) and child["connector_key"] == parent["connector_key"]:
                if child["attributes"].get("associated_resource_id"):
                    continue
                _edge(built, "contains", parent["source_key"], child["source_key"], child, ARM_RULE, [parent["source_key"], child["source_key"]])


def _group_edge(built, by_key, connector, attributes, collected, now, maturity) -> None:
    group_id = str(attributes.get("group_id") or "")
    member_id = str(attributes.get("member_id") or "")
    group = next((node for node in by_key.values() if node["vendor_id"] == group_id and node["connector_key"] == connector), None)
    member = next((node for node in by_key.values() if node["vendor_id"] == member_id and node["connector_key"] == connector), None)
    subject = source_key(connector, member_id or group_id or "membership")
    if group is None or member is None:
        _conflict(built, subject, "dangling_reference", "missing_member")
        return
    _edge(built, "member_of", member["source_key"], group["source_key"], member, GROUP_RULE, [member["source_key"], group["source_key"]])
    _ = (collected, now, maturity)


def _memberships(built, by_key, memberships, actor, now) -> None:
    for service_key, member_key, role in memberships:
        service = by_key.get(service_key)
        member = by_key.get(member_key)
        if service is None or member is None or service["node_type"] != "business_service":
            _conflict(built, service_key, "dangling_reference", "missing_membership")
            continue
        built.memberships.append({
            "service_key": service_key,
            "member_key": member_key,
            "role": role,
            "evidence_mode": "manual",
            "maturity": "synthetic",
            "derivation_rule": None,
            "limitations": [NOT_A_FINDING, "manual_membership"],
            "actor": clean_label(actor),
            "scoped_at": now,
        })
        if role == "entry":
            _manual_edge(built, "serves", member_key, service_key, member)
        elif role == "administration":
            _manual_edge(built, "administered_through", service_key, member_key, service)


def _ambiguity(built: Projection, by_key: dict[str, dict]) -> None:
    linked = {
        tuple(sorted((edge["from_key"], edge["to_key"])))
        for edge in built.edges
        if edge["derivation_rule"] == SITE_KEY_RULE
    }
    nodes = list(by_key.values())
    for index, left in enumerate(nodes):
        for right in nodes[index + 1:]:
            pair = tuple(sorted((left["source_key"], right["source_key"])))
            if pair in linked or left["connector_key"] == right["connector_key"]:
                continue
            if left["label"] == right["label"] and left["label"] != "unnamed":
                _conflict(built, left["source_key"], "ambiguous_identity", "shared_label")
            left_address = str(left["attributes"].get("address") or "")
            right_address = str(right["attributes"].get("address") or "")
            if left_address and left_address == right_address:
                _conflict(built, left["source_key"], "duplicate_address", "shared_address")


def _cap_degree(built: Projection) -> None:
    counts: dict[str, int] = {}
    kept: list[dict] = []
    for edge in built.edges:
        if counts.get(edge["from_key"], 0) >= MAX_DEGREE or counts.get(edge["to_key"], 0) >= MAX_DEGREE:
            built.limitations.append("degree_capped")
            continue
        counts[edge["from_key"]] = counts.get(edge["from_key"], 0) + 1
        counts[edge["to_key"]] = counts.get(edge["to_key"], 0) + 1
        kept.append(edge)
    built.edges = kept


def _edge(built, edge_type, from_key, to_key, origin, rule, contributors, extra=None) -> None:
    if edge_type not in EDGE_TYPES or from_key == to_key:
        raise GraphFailure("vocabulary_rejected")
    limitations = [NOT_A_FINDING, *(extra or [])]
    item = {
        "source_key": f"{edge_type}|{from_key}|{to_key}|{rule}",
        "edge_type": edge_type,
        "from_key": from_key,
        "to_key": to_key,
        "maturity": origin["maturity"],
        "evidence_mode": "inferred",
        "connector_key": origin["connector_key"],
        "source_contract": origin["source_contract"],
        "source_record_id": origin["source_record_id"],
        "collected_at": origin["collected_at"],
        "materialized_at": origin["materialized_at"],
        "freshness": origin["freshness"],
        "confidence": "derived",
        "limitations": sorted(set(limitations)),
        "lifecycle": "active",
        "derivation_rule": rule,
        "derivation_version": SITE_KEY_VERSION if rule == SITE_KEY_RULE else "1",
        "contributing": sorted(set(contributors)),
    }
    if any(edge["source_key"] == item["source_key"] for edge in built.edges):
        return
    built.edges.append(item)


def _manual_edge(built, edge_type, from_key, to_key, origin) -> None:
    item = {
        "source_key": f"{edge_type}|{from_key}|{to_key}|manual",
        "edge_type": edge_type,
        "from_key": from_key,
        "to_key": to_key,
        "maturity": "synthetic",
        "evidence_mode": "manual",
        "connector_key": origin["connector_key"],
        "source_contract": origin["source_contract"],
        "source_record_id": origin["source_record_id"],
        "collected_at": origin["collected_at"],
        "materialized_at": origin["materialized_at"],
        "freshness": origin["freshness"],
        "confidence": "stated",
        "limitations": [NOT_A_FINDING, NOT_REACHABILITY],
        "lifecycle": "active",
        "derivation_rule": None,
        "derivation_version": None,
        "contributing": [],
    }
    built.edges.append(item)


def _observe(built, key, connector, contract, external_id, evidence, maturity, collected, now, attributes) -> dict:
    item = {
        "subject_key": key,
        "connector_key": connector,
        "source_contract": contract,
        "source_record_id": external_id,
        "evidence_mode": evidence,
        "maturity": maturity,
        "collected_at": collected,
        "materialized_at": now,
        "payload": attributes,
    }
    built.observations.append(item)
    return item


def _conflict(built, subject, conflict_type, detail) -> None:
    if conflict_type not in CONFLICT_TYPES:
        raise GraphFailure("vocabulary_rejected")
    item = {"subject_key": subject, "conflict_type": conflict_type, "detail_code": detail, "limitations": [NOT_A_FINDING]}
    if item not in built.conflicts:
        built.conflicts.append(item)


def _node_type(kind: str, attributes: dict) -> str | None:
    if kind in UNMAPPED_KINDS:
        return None
    if kind == "principal":
        principal = str(attributes.get("principal_type") or "")
        if principal == "group":
            return "group"
        if principal in {"servicePrincipal", "service_principal"}:
            return "service_principal"
        if principal in {"user", "identity"}:
            return "identity"
        return None
    if kind == "interface":
        name = str(attributes.get("name") or "")
        return "logical_interface" if "." in name else "network_interface"
    return KIND_NODE.get(kind)


def _maturity(truth: str, envelope_maturity: str, envelope_mode: str) -> str:
    if truth == "synthetic":
        return "synthetic"
    if truth == "live_verified" and envelope_maturity == "live_verified" and envelope_mode == "live":
        return "live_verified"
    return "fixture_tested"


def _evidence(truth: str) -> str:
    if truth == "observed":
        return "observed"
    if truth == "configured":
        return "configured"
    if truth in {"manual", "synthetic"}:
        return "manual"
    if truth == "stale":
        return "observed"
    return "configured"


def _admin_oper_conflict(attributes: dict) -> bool:
    admin = attributes.get("admin_status")
    oper = attributes.get("oper_status")
    return admin in {"up", "down"} and oper in {"up", "down"} and admin != oper


def _limitations(raw, dropped: list[str]) -> list[str]:
    values = [str(item) for item in raw or [] if re.fullmatch(r"[a-z0-9_]{1,64}", str(item))]
    return sorted(set([*values, *dropped, NOT_A_FINDING]))


def _collected(value, now: datetime) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return now
