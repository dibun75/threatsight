"""Fixed correlation rules. Clients cannot supply match expressions."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from threatsight_api.correlation.bounds import (
    MAX_COMPARISONS,
    MAX_DEPTH,
    MAX_EVENTS,
    MAX_FANOUT,
    MAX_MATCHES_PER_ASSET,
    MAX_MATCHES_PER_EVENT,
    MAX_NODES,
    MAX_RESULTS,
    MAX_SECONDS,
)
from threatsight_api.correlation.versions import (
    COMPARATOR,
    parse_range,
    parse_version,
    range_is_complete,
    version_relation,
)
from threatsight_api.correlation.vocabulary import GLOBAL_LIMITATIONS, RULESET_VERSION
from threatsight_api.graph.sanitize import plain_text

_APPROVED_EDGES = frozenset({"depends_on", "serves", "contains", "sourced_from"})
_CONNECTOR_VENDOR = {
    "junos.device": ("juniper", "junos"),
    "meraki.dashboard": ("meraki", "meraki"),
}
_RANK = {"inferred": 0, "configured": 1, "manual": 2, "observed": 3}


class CorrelationStop(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def correlate(
    events: list[dict],
    nodes: list[dict],
    edges: list[dict],
    memberships: list[dict],
    aliases: list[dict] | None = None,
    *,
    elapsed: Callable[[], float] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> dict:
    spent = elapsed or (lambda: 0.0)
    if cancelled and cancelled():
        raise CorrelationStop("cancelled")
    if spent() > MAX_SECONDS:
        raise CorrelationStop("bound_exceeded")
    limitations = list(GLOBAL_LIMITATIONS)
    chosen_events = list(events)
    chosen_nodes = list(nodes)
    if len(chosen_events) > MAX_EVENTS:
        limitations.append("event_limit")
        chosen_events = chosen_events[:MAX_EVENTS]
    if len(chosen_nodes) > MAX_NODES:
        limitations.append("node_limit")
        chosen_nodes = chosen_nodes[:MAX_NODES]
    catalog = _aliases(aliases or [])
    indexed = _index(chosen_nodes, edges)
    comparisons = 0
    per_event: dict[str, int] = defaultdict(int)
    per_asset: dict[str, int] = defaultdict(int)
    grouped: dict[tuple, dict] = {}
    for event in chosen_events:
        if cancelled and cancelled():
            raise CorrelationStop("cancelled")
        if spent() > MAX_SECONDS:
            raise CorrelationStop("bound_exceeded")
        for node in indexed["candidates"]:
            comparisons += 1
            if comparisons > MAX_COMPARISONS:
                limitations.append("comparison_limit")
                break
            if per_event[event["event_id"]] >= MAX_MATCHES_PER_EVENT or per_asset[node["source_key"]] >= MAX_MATCHES_PER_ASSET:
                limitations.append("match_limit")
                continue
            found = _compare(event, node, catalog)
            if found is None:
                continue
            key = (found["rule_id"], found["cve"], node["source_key"])
            current = grouped.get(key)
            if current is None:
                found["event_ids"] = [event["event_id"]]
                found["cluster_keys"] = [event["cluster_key"]] if event.get("cluster_key") else []
                found["sources"] = [event["source_key"]]
                grouped[key] = found
                per_event[event["event_id"]] += 1
                per_asset[node["source_key"]] += 1
            else:
                _merge(current, found, event)
        else:
            continue
        break
    results = []
    for item in grouped.values():
        services, walk_limit = _services(item["asset_key"], indexed, memberships)
        item["services"] = services
        item["limitations"] = sorted(set([*GLOBAL_LIMITATIONS, *item["limitations"], *walk_limit]))
        item["explanation"] = plain_text(item["explanation"])[:400]
        results.append(item)
    results.sort(key=lambda item: (item["cve"], item["asset_key"], item["rule_id"], item["state"]))
    return {
        "ruleset_version": RULESET_VERSION,
        "results": results[:MAX_RESULTS],
        "limitations": sorted(set(limitations)),
        "partial": "event_limit" in limitations or "comparison_limit" in limitations or "node_limit" in limitations,
    }


def _aliases(rows: list[dict]) -> dict[tuple[str, str], tuple[str, str]]:
    found = {}
    for row in rows[:100]:
        alias = (_token(row.get("alias_vendor")), _token(row.get("alias_product")))
        canonical = (_token(row.get("vendor")), _token(row.get("product")))
        if all(alias) and all(canonical):
            found[alias] = canonical
    return found


def _index(nodes: list[dict], edges: list[dict]) -> dict:
    by_key = {node["source_key"]: node for node in nodes}
    children = {edge["from_key"] for edge in edges if edge["edge_type"] == "sourced_from" and by_key.get(edge["from_key"], {}).get("node_type") == "software_version"}
    parents = {edge["from_key"]: edge["to_key"] for edge in edges if edge["edge_type"] == "sourced_from"}
    candidates = []
    for node in nodes:
        if node["node_type"] not in {"device", "software_version", "cloud_resource", "application_service"}:
            continue
        if node["node_type"] == "device" and node["source_key"] in {parents.get(child) for child in children}:
            if not str(node.get("attributes", {}).get("firmware_family") or ""):
                continue
        candidates.append(node)
    outgoing: dict[str, list[dict]] = defaultdict(list)
    incoming: dict[str, list[dict]] = defaultdict(list)
    for edge in edges:
        if edge["edge_type"] in _APPROVED_EDGES:
            outgoing[edge["from_key"]].append(edge)
            incoming[edge["to_key"]].append(edge)
    return {"nodes": by_key, "parents": parents, "candidates": candidates, "outgoing": outgoing, "incoming": incoming}


def _compare(event: dict, node: dict, aliases: dict) -> dict | None:
    parent_key = _index_parent(node, event)
    _ = parent_key
    identity = _identity(node, aliases)
    cve = next((item for item in event.get("cves") or [] if _cve(item)), "")
    if not cve or identity is None:
        cloud = _cloud(event, node)
        return None if cloud is None else _result(event, node, cve or "CLOUD", cloud[0], cloud[1], cloud[2], cloud[3], cloud[4])
    vendor, product, version_text, cpe, purl, firmware, family = identity
    event_vendor = {_token(item) for item in event.get("vendors") or []}
    event_product = {_token(item) for item in event.get("products") or []}
    alias_hit = aliases.get((vendor, product))
    canonical = alias_hit or (vendor, product)
    product_match = canonical[0] in event_vendor and canonical[1] in event_product
    cpe_parts = _cpe(cpe)
    event_cpes = [_cpe(item) for item in event.get("cpes") or []]
    event_cpes = [item for item in event_cpes if item]
    exact_cpe = any(item["vendor"] == cpe_parts["vendor"] and item["product"] == cpe_parts["product"] and item["version"] == cpe_parts["version"] and item["version"] != "*" for item in event_cpes) if cpe_parts else False
    parsed = parse_version(version_text)
    ranges = [(expr, parse_range(expr)) for expr in (event.get("version_ranges") or [])[:4]]
    relations = []
    complete = False
    for expr, pieces in ranges:
        if pieces is None or parsed is None:
            relations.append("unknown")
            continue
        if range_is_complete(pieces):
            complete = True
            relations.append(version_relation(parsed, pieces))
        else:
            relations.append("unknown")
    purl_match = bool(purl) and purl in {str(item) for item in event.get("purls") or []}
    if family and node.get("connector_key") == "meraki.dashboard":
        rule, state, missing = _firmware(parsed, relations, complete)
        return _result(event, node, cve, rule, state, missing, _version_evidence(version_text or firmware, relations), {"firmware_family": family, "vendor": vendor, "product": product})
    if node.get("connector_key") == "junos.device" or canonical == ("juniper", "junos"):
        if parsed is None:
            return _result(event, node, cve, "junos-version-v1", "unknown", ["unsupported_version"], _version_evidence(version_text, ["unknown"]), {"vendor": "juniper", "product": "junos"})
    pinned = any(str(item).strip().startswith("=") and not str(item).strip().startswith((">=", "<=")) for item in (event.get("version_ranges") or []))
    if exact_cpe and parsed is not None and "inside" in relations and pinned:
        return _result(event, node, cve, "cve-cpe-exact-v1", "confirmed_identifier_match", [], _version_evidence(version_text, relations), {"cpe": cpe, "vendor": vendor, "product": product})
    if purl_match and parsed is not None and "inside" in relations:
        return _result(event, node, cve, "software-identifier-v1", "version_supported_candidate", [], _version_evidence(version_text, relations), {"purl": purl})
    if product_match and parsed is not None and "inside" in relations and complete:
        rule = "vendor-product-alias-v1" if alias_hit else "cve-version-range-v1"
        return _result(event, node, cve, rule, "version_supported_candidate", [], _version_evidence(version_text, relations), {"vendor": canonical[0], "product": canonical[1], "alias": bool(alias_hit)})
    if product_match and parsed is not None and relations and "outside" in relations and "inside" not in relations and "unknown" not in relations:
        return _result(event, node, cve, "cve-version-range-v1", "not_applicable_by_evidence", [], _version_evidence(version_text, relations), {"vendor": canonical[0], "product": canonical[1]})
    if product_match and parsed is None and version_text:
        return _result(event, node, cve, "junos-version-v1" if "junos" in canonical else "cve-version-range-v1", "unknown", ["unsupported_version"], _version_evidence(version_text, ["unknown"]), {"vendor": canonical[0], "product": canonical[1]})
    if product_match and not version_text:
        return _result(event, node, cve, "vendor-product-alias-v1" if alias_hit else "cve-version-range-v1", "possible_match", ["missing_version"], {"original": "", "comparator": COMPARATOR, "relation": "unknown"}, {"vendor": canonical[0], "product": canonical[1]})
    cloud = _cloud(event, node)
    if cloud:
        return _result(event, node, cve, cloud[0], cloud[1], cloud[2], cloud[3], cloud[4])
    return None


def _index_parent(node: dict, event: dict) -> str:
    _ = (node, event)
    return ""


def _firmware(parsed, relations, complete) -> tuple[str, str, list[str]]:
    if parsed is None:
        return "meraki-firmware-v1", "unknown", ["unsupported_version"]
    if complete and "inside" in relations:
        return "meraki-firmware-v1", "version_supported_candidate", []
    if complete and "outside" in relations and "unknown" not in relations:
        return "meraki-firmware-v1", "not_applicable_by_evidence", []
    return "meraki-firmware-v1", "possible_match", ["incomplete_range"]


def _cloud(event: dict, node: dict) -> tuple | None:
    service = _token(node.get("attributes", {}).get("cloud_service"))
    scope = _token(node.get("attributes", {}).get("cloud_scope"))
    if not service or not scope:
        return None
    if _token(event.get("cloud_service")) != service or _token(event.get("cloud_scope")) != scope:
        return None
    cve = next((item for item in event.get("cves") or [] if _cve(item)), "")
    if not cve:
        return None
    return ("cloud-service-advisory-v1", "possible_match", ["cloud_scope_only"], {"original": "", "comparator": COMPARATOR, "relation": "unknown"}, {"cloud_service": service, "cloud_scope": scope})


def _identity(node: dict, aliases: dict) -> tuple | None:
    _ = aliases
    attributes = node.get("attributes") or {}
    connector = _CONNECTOR_VENDOR.get(node.get("connector_key") or "")
    vendor = _token(attributes.get("vendor")) or (connector[0] if connector else "")
    product = _token(attributes.get("product")) or (connector[1] if connector else "")
    version = str(attributes.get("version") or attributes.get("firmware") or "")
    cpe = str(attributes.get("cpe") or "")
    purl = str(attributes.get("purl") or "")
    firmware = str(attributes.get("firmware") or "")
    family = _token(attributes.get("firmware_family"))
    cpe_parts = _cpe(cpe)
    if cpe_parts:
        vendor = vendor or cpe_parts["vendor"]
        product = product or cpe_parts["product"]
        if not version and cpe_parts["version"] != "*":
            version = cpe_parts["version"]
    if node.get("node_type") == "cloud_resource":
        return vendor, product, version, cpe, purl, firmware, family
    if not vendor and not product and not cpe and not purl and not family:
        return None
    return vendor, product, version, cpe, purl, firmware, family


def _merge(current: dict, found: dict, event: dict) -> None:
    if event["event_id"] not in current["event_ids"]:
        current["event_ids"].append(event["event_id"])
        current["event_ids"].sort()
    if event.get("cluster_key") and event["cluster_key"] not in current["cluster_keys"]:
        current["cluster_keys"].append(event["cluster_key"])
    if event["source_key"] not in current["sources"]:
        current["sources"].append(event["source_key"])
    if event.get("freshness") == "stale":
        current["freshness"] = "stale"
        current["limitations"].append("stale_input")
    current["limitations"].extend(found.get("limitations") or [])
    states = {current["state"], found["state"]}
    relations = {current["version_evidence"].get("relation"), found["version_evidence"].get("relation")}
    if "inside" in relations and "outside" in relations:
        current["state"] = "conflicting"
        current["limitations"].append("conflicting_ranges")
    elif states == {"not_applicable_by_evidence", "version_supported_candidate"} or states == {"not_applicable_by_evidence", "confirmed_identifier_match"}:
        current["state"] = "conflicting"
        current["limitations"].append("conflicting_ranges")
    elif found["state"] == "confirmed_identifier_match":
        current["state"] = "confirmed_identifier_match"
        current["rule_id"] = found["rule_id"]
    current["source_count"] = len(current["event_ids"])


def _result(event, node, cve, rule, state, missing, version_evidence, identifier) -> dict:
    limitations = []
    if event.get("freshness") == "stale" or node.get("freshness") == "stale":
        limitations.append("stale_input")
    if event.get("exploitation_status") == "known_exploited":
        limitations.append("kev_is_not_customer_attack")
    if event.get("epss_score") is not None:
        limitations.append("epss_is_dated_probability")
    return {
        "state": state,
        "rule_id": rule,
        "rule_version": "1",
        "cve": cve,
        "asset_key": node["source_key"],
        "event_ids": [event["event_id"]],
        "cluster_keys": [event["cluster_key"]] if event.get("cluster_key") else [],
        "sources": [event["source_key"]],
        "source_count": 1,
        "services": [],
        "evidence_mode": node.get("evidence_mode") or "configured",
        "maturity": node.get("maturity") if node.get("maturity") in {"synthetic", "fixture_tested", "live_verified"} else "fixture_tested",
        "freshness": "stale" if "stale_input" in limitations else (node.get("freshness") or "untested"),
        "identifier_evidence": identifier,
        "version_evidence": version_evidence,
        "provenance": {
            "source": event.get("source_key") or "",
            "parser": (event.get("provenance") or {}).get("parser") or RULESET_VERSION,
        },
        "geography": {
            "authority_jurisdictions": list(event.get("authority_jurisdictions") or []),
            "target_countries": list(event.get("target_countries") or []),
            "victim_countries": list(event.get("victim_countries") or []),
            "infrastructure_countries": list(event.get("infrastructure_countries") or []),
            "prevalence_countries": list(event.get("prevalence_countries") or []),
        },
        "epss_score": event.get("epss_score"),
        "epss_date": event.get("epss_date"),
        "exploitation_status": event.get("exploitation_status") or "unknown",
        "limitations": limitations,
        "missing_facts": missing,
        "explanation": _explain(state, cve, node["source_key"]),
    }


def _explain(state: str, cve: str, asset: str) -> str:
    return f"Rule {state} compared {cve} with {asset}. Version and identifier evidence are attached. Geography roles stay separate."


def _version_evidence(original: str, relations: list[str]) -> dict:
    relation = "unknown"
    if "inside" in relations and "outside" in relations:
        relation = "conflicting"
    elif "inside" in relations:
        relation = "inside"
    elif "outside" in relations and "unknown" not in relations:
        relation = "outside"
    return {"original": original[:64], "comparator": COMPARATOR, "relation": relation}


def _services(start: str, indexed: dict, memberships: list[dict]) -> tuple[list[dict], list[str]]:
    seen = {start}
    queue = [(start, 0, "observed")]
    found: dict[str, str] = {}
    limitations = []
    while queue:
        key, depth, mode = queue.pop(0)
        if depth >= MAX_DEPTH:
            limitations.append("propagation_depth")
            continue
        members = [item for item in memberships if item["member_key"] == key]
        for item in members[:MAX_FANOUT]:
            found[item["service_key"]] = _weaker(mode, "manual")
        if len(members) > MAX_FANOUT:
            limitations.append("fanout_limit")
        neighbors = indexed["outgoing"].get(key, []) + indexed["incoming"].get(key, [])
        neighbors = sorted(neighbors, key=lambda item: (item["edge_type"], item["source_key"]))
        if len(neighbors) > MAX_FANOUT:
            limitations.append("fanout_limit")
            neighbors = neighbors[:MAX_FANOUT]
        for edge in neighbors:
            other = edge["to_key"] if edge["from_key"] == key else edge["from_key"]
            if other in seen:
                limitations.append("cycle_terminated")
                continue
            seen.add(other)
            queue.append((other, depth + 1, _weaker(mode, edge.get("evidence_mode") or "inferred")))
            node = indexed["nodes"].get(other)
            if node and node.get("node_type") == "business_service":
                found[other] = _weaker(mode, edge.get("evidence_mode") or "inferred")
    services = [{"source_key": key, "evidence_mode": found[key]} for key in sorted(found)]
    return services, limitations


def _weaker(left: str, right: str) -> str:
    if _RANK.get(left, 1) <= _RANK.get(right, 1):
        return left if left in _RANK else right
    return right


def _cpe(value: object) -> dict | None:
    text = str(value or "")
    if len(text) > 80 or text.count(":") != 12 or not text.startswith("cpe:2.3:"):
        return None
    parts = text.split(":")
    if parts[2] not in {"a", "o", "h"}:
        return None
    return {"vendor": _token(parts[3]), "product": _token(parts[4]), "version": parts[5]}


def _cve(value: object) -> bool:
    text = str(value or "").upper()
    if len(text) < 13 or len(text) > 20 or not text.startswith("CVE-"):
        return False
    year, dash, number = text[4:].partition("-")
    return bool(dash) and len(year) == 4 and year.isdigit() and 4 <= len(number) <= 7 and number.isdigit()


def _token(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text or len(text) > 64:
        return ""
    if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for ch in text):
        return ""
    return text
