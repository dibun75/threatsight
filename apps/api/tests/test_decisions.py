from threatsight_api.decisions.project import derive_state, project_one, summarize


def _service(name: str, key: str) -> dict:
    return {"id": key, "label": name, "source_key": key, "maturity": "synthetic", "purpose": name}


def _match(cve: str, asset: str, state: str, service: str, mode: str = "manual") -> dict:
    return {
        "cve": cve,
        "state": state,
        "asset_key": asset,
        "maturity": "fixture_tested",
        "freshness": "stale",
        "services": [{"source_key": service, "evidence_mode": mode}],
        "epss_score": None,
        "epss_date": None,
    }


def test_states_follow_evidence_and_do_not_score() -> None:
    assert derive_state(has_membership=False, live_matches=[], reference_matches=[], paths=[], controls=[]) == "insufficient_data"
    assert derive_state(has_membership=True, live_matches=[], reference_matches=[], paths=[], controls=[]) == "no_current_relevant_match"
    assert derive_state(has_membership=True, live_matches=[{"cve": "CVE-1"}], reference_matches=[], paths=[], controls=[]) == "investigation_required"
    assert derive_state(
        has_membership=True,
        live_matches=[],
        reference_matches=[],
        paths=[],
        controls=[{"verdict": "FAIL", "freshness": "current", "open_finding": True}],
    ) == "action_required"
    assert derive_state(
        has_membership=True,
        live_matches=[],
        reference_matches=[],
        paths=[],
        controls=[{"verdict": "PASS", "freshness": "stale", "open_finding": False}],
    ) == "evidence_stale"
    assert derive_state(
        has_membership=True,
        live_matches=[],
        reference_matches=[],
        paths=[],
        controls=[{"verdict": "PASS", "freshness": "current", "open_finding": False}],
    ) == "verified_current"


def test_fixture_match_is_not_counted_as_live_and_paths_stay_on_their_service() -> None:
    ordering = project_one(
        service=_service("Customer ordering", "service:ordering"),
        members=[{"source_key": "device:widget", "label": "widget", "role": "dependency", "evidence_mode": "manual"}],
        matches=[_match("CVE-1", "device:widget", "version_supported_candidate", "service:ordering")],
        advisories=[{"title": "Fixture", "cves": ["CVE-1"], "maturity": "fixture_tested", "kev_listed": False, "epss_score": None, "withdrawn": False}],
        results=[{"state": "unknown", "freshness": "stale", "evidence_modes": ["configured"], "explanation": "stale", "node_keys": ["device:widget"]}],
        controls=[],
        snapshot_current=True,
    )
    remote = project_one(
        service=_service("Remote access", "service:remote"),
        members=[{"source_key": "device:edge", "label": "edge", "role": "network", "evidence_mode": "manual"}],
        matches=[_match("CVE-2", "device:edge", "unknown", "service:remote", "inferred")],
        advisories=[],
        results=[{"state": "unknown", "freshness": "stale", "evidence_modes": ["configured"], "explanation": "other", "node_keys": ["device:other"]}],
        controls=[],
        snapshot_current=True,
    )
    assert ordering["live_count"] == 0
    assert ordering["reference_count"] == 1
    assert ordering["path_count"] == 1
    assert remote["path_count"] == 0
    assert ordering["explanation"] != remote["explanation"]
    body = summarize([ordering, remote])
    assert body["outcomes"]["live_relevant_advisories"] == 0
    assert "score" not in body["does_not_mean"]
    linked = project_one(
        service=_service("Privileged administration", "service:admin"),
        members=[{"source_key": "device:gateway", "label": "gateway", "role": "member", "evidence_mode": "configured"}],
        matches=[_match("CVE-2024-2001", "device:gateway", "version_supported_candidate", "service:admin")],
        advisories=[],
        results=[],
        controls=[{"service_key": "service:admin", "evidence_status": "gap", "decision": "Validate the privileged assignment.", "owner_state": "not_assigned"}],
        snapshot_current=True,
    )
    assert linked["control_gap"] == "Configured, not observed."
    assert linked["required_decision"] == "Validate the privileged assignment."
    assert "No control record" not in linked["explanation"]


def test_live_advisory_stays_separate_from_a_withdrawn_row() -> None:
    row = project_one(
        service=_service("Customer ordering", "service:ordering"),
        members=[{"source_key": "device:widget", "label": "widget", "role": "dependency", "evidence_mode": "manual"}],
        matches=[_match("CVE-9", "device:widget", "possible_match", "service:ordering")],
        advisories=[
            {"title": "Withdrawn", "cves": ["CVE-9"], "maturity": "live_verified", "kev_listed": False, "epss_score": None, "withdrawn": True},
            {"title": "Live", "cves": ["CVE-9"], "maturity": "live_verified", "kev_listed": True, "epss_score": 0.2, "withdrawn": False},
        ],
        results=[],
        controls=[],
        snapshot_current=True,
    )
    assert row["live_count"] == 1
    assert row["reference_count"] == 0
    assert row["live_matches"][0]["title"] == "Live"


def test_unrelated_control_is_excluded() -> None:
    row = project_one(
        service=_service("Remote access", "service:remote"),
        members=[{"source_key": "device:edge", "label": "edge", "role": "network", "evidence_mode": "manual"}],
        matches=[],
        advisories=[],
        results=[],
        controls=[{"service_key": "service:ordering", "identifier": "CTRL-002", "title": "Tool", "verdict": "FAIL", "freshness": "current", "open_finding": True}],
        snapshot_current=True,
    )
    assert row["control_count"] == 0
    assert row["state"] == "no_current_relevant_match"
    assert "control_not_mapped" in row["limitations"]
