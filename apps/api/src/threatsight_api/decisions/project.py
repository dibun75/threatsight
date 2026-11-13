"""Deterministic service decisions. This module does not read the database."""

from __future__ import annotations

from threatsight_api.presentation import public_match, public_name

STATES = (
    "action_required",
    "investigation_required",
    "evidence_stale",
    "verified_current",
    "no_current_relevant_match",
    "insufficient_data",
)
_RANK = {name: index for index, name in enumerate(STATES)}
_LIMIT = 5


def derive_state(
    *,
    has_membership: bool,
    live_matches: list[dict],
    reference_matches: list[dict],
    paths: list[dict],
    controls: list[dict],
) -> str:
    if not has_membership:
        return "insufficient_data"
    failed = [item for item in controls if item.get("open_finding") and item.get("verdict") == "FAIL"]
    if failed:
        return "action_required"
    if any(item.get("freshness") == "stale" for item in controls):
        return "evidence_stale"
    if controls and not live_matches and not reference_matches and not paths:
        if all(item.get("verdict") == "PASS" and item.get("freshness") == "current" for item in controls):
            return "verified_current"
    if live_matches or reference_matches or paths:
        return "investigation_required"
    return "no_current_relevant_match"


def explain(state: str, *, service: str, live: list[dict], reference: list[dict], paths: list[dict], control_gap: str) -> str:
    if state == "insufficient_data":
        return f"{service} has no explicit membership in the current snapshot. The missing membership is not proof of safety."
    if state == "no_current_relevant_match":
        return f"No current advisory match names {service}. That is not proof the service is safe."
    if state == "action_required":
        return f"A mapped control for {service} has an open failed result. The failure is a recorded test, not a compliance status."
    if state == "evidence_stale":
        return f"A mapped control for {service} has evidence outside its freshness window."
    if state == "verified_current":
        return f"A mapped control for {service} has a current passing result for its recorded scope. That is not a statement that the service is safe."
    lead = f"No live-verified advisory currently matches {service}."
    if live:
        first = live[0]
        lead = f"A live-verified advisory matches {service} on {first.get('asset_label') or 'a recorded asset'}."
    extra = ""
    if reference:
        first = reference[0]
        label = public_match(str(first.get("match_state") or ""))
        extra = f" Reference scenario: {label} on {public_name(str(first.get('asset_label') or ''))}."
        if label == "Unknown":
            extra += " The recorded version cannot be ordered against the advisory, so applicability is unknown."
    path = ""
    if paths:
        path = f" {len(paths)} candidate path result names this service or a member. The path is not proven delivery."
    return f"{lead}{extra}{path} {control_gap}".strip()


def project_one(
    *,
    service: dict,
    members: list[dict],
    matches: list[dict],
    advisories: list[dict],
    results: list[dict],
    controls: list[dict],
    snapshot_current: bool,
) -> dict:
    keys = {service["source_key"]} | {item["source_key"] for item in members}
    own_matches = []
    for item in matches:
        named = next((entry for entry in item.get("services") or [] if entry.get("source_key") == service["source_key"]), None)
        if named is None:
            continue
        own_matches.append({**item, "relationship": named.get("evidence_mode") or "unknown"})
    by_cve: dict[str, list[dict]] = {}
    for advisory in advisories:
        if advisory.get("withdrawn"):
            continue
        for cve in advisory.get("cves") or []:
            by_cve.setdefault(cve, []).append(advisory)
    live = []
    reference = []
    for item in own_matches:
        linked = by_cve.get(item.get("cve"), [])
        live_row = next((row for row in linked if row.get("maturity") == "live_verified"), None)
        chosen = live_row or (linked[0] if linked else None)
        maturity = chosen.get("maturity") if chosen else item.get("maturity")
        row = {
            "title": (chosen or {}).get("title") or item.get("cve"),
            "cve": item.get("cve"),
            "maturity": maturity,
            "match_state": item.get("state"),
            "asset_label": item.get("asset_key"),
            "relationship": item.get("relationship"),
            "freshness": item.get("freshness"),
            "kev_listed": bool((chosen or {}).get("kev_listed")),
            "epss_score": (chosen or {}).get("epss_score", item.get("epss_score")),
            "epss_date": (chosen or {}).get("epss_date") or item.get("epss_date"),
        }
        if maturity == "live_verified":
            live.append(row)
        else:
            reference.append(row)
    own_paths = []
    for item in results:
        if keys.intersection(set(item.get("node_keys") or [])):
            own_paths.append(item)
    mapped = [item for item in controls if item.get("service_key") == service["source_key"]]
    if not mapped:
        gap = "No control record names this service."
    elif mapped[0].get("evidence_status") == "gap":
        gap = "Configured, not observed."
    else:
        gap = "Unknown state."
    state = derive_state(
        has_membership=bool(members),
        live_matches=live,
        reference_matches=reference,
        paths=own_paths,
        controls=mapped,
    )
    name = service["label"]
    return {
        "service_id": service["id"],
        "name": name,
        "source_key": service["source_key"],
        "synthetic": service.get("maturity") == "synthetic" or service.get("maturity") == "fixture_tested",
        "purpose": service.get("purpose") or "Business service recorded in the current snapshot.",
        "state": state,
        "explanation": explain(state, service=name, live=live[:1], reference=reference[:1], paths=own_paths[:_LIMIT], control_gap=gap),
        "snapshot_current": snapshot_current,
        "members": members[:_LIMIT],
        "live_matches": live[:_LIMIT],
        "reference_matches": reference[:_LIMIT],
        "live_count": len(live),
        "reference_count": len(reference),
        "paths": [
            {
                "state": item.get("state"),
                "freshness": item.get("freshness"),
                "evidence_modes": list(item.get("evidence_modes") or [])[:4],
                "explanation": item.get("explanation"),
                "node_keys": list(item.get("node_keys") or [])[:6],
            }
            for item in own_paths[:_LIMIT]
        ],
        "path_count": len(own_paths),
        "controls": mapped[:_LIMIT],
        "control_count": len(mapped),
        "control_gap": gap,
        "required_decision": (mapped[0].get("decision") if mapped else None) or _step(state, bool(live)),
        "owner_state": (mapped[0].get("owner_state") if mapped else None) or "not_assigned",
        "recommended_step": _step(state, bool(live)),
        "limitations": _limits(snapshot_current, bool(members), bool(mapped)),
    }


def summarize(items: list[dict]) -> dict:
    ordered = sorted(items, key=lambda item: (_RANK.get(item["state"], 9), -item["live_count"], item["name"]))
    live_total = sum(item["live_count"] for item in items)
    return {
        "services": ordered,
        "decisions": ordered[:3],
        "outcomes": {
            "action_required": sum(item["state"] == "action_required" for item in items),
            "investigation_required": sum(item["state"] == "investigation_required" for item in items),
            "evidence_stale": sum(item["state"] == "evidence_stale" for item in items),
            "verified_current": sum(item["state"] == "verified_current" for item in items),
            "live_relevant_advisories": live_total,
        },
        "does_not_mean": "A decision is a reading of recorded evidence. It is not an incident, a reachability proof, or a compliance result.",
    }


def _step(state: str, live: bool) -> str:
    if state == "action_required":
        return "Review the open failed control result. The recommendation is not a recorded work order."
    if state == "insufficient_data":
        return "Record an explicit membership before treating this service as decided."
    if not live:
        return "No live-verified advisory matches this service. A reference scenario, when present, is not live exposure."
    return "Investigate the matched asset. The match is not proof of exposure."


def _limits(current: bool, membership: bool, mapped: bool) -> list[str]:
    limits = ["not_packet_delivery", "not_a_compliance_result"]
    if not current:
        limits.append("snapshot_not_current")
    if not membership:
        limits.append("membership_missing")
    if not mapped:
        limits.append("control_not_mapped")
    return limits
