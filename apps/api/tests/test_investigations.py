from threatsight_api.investigations.project import classification, path_steps


def test_classifications_stay_exact() -> None:
    assert classification("confirmed_identifier_match") == "Identifier match"
    assert classification("version_supported_candidate") == "Version-supported candidate"
    assert classification("possible_match") == "Possible match"
    assert classification("unknown") == "Unknown"
    assert classification("conflicting") == "Conflicting"
    assert classification("not_applicable_by_evidence") == "Not applicable by evidence"
    assert classification("anything-else") == "Unknown"


def test_missing_edge_is_unknown_not_safety() -> None:
    steps = path_steps(["missing-edge"], {})
    assert steps[0]["evidence_state"] == "Unknown"
    assert "not proof" in steps[0]["limitation"]
    assert "reachability" not in steps[0]["limitation"] or "not proven" in steps[0]["limitation"] or "not proof" in steps[0]["limitation"]


def test_stored_edge_keeps_source_and_does_not_claim_delivery() -> None:
    steps = path_steps(["edge-1"], {
        "edge-1": {
            "id": "edge",
            "edge_type": "routes_to",
            "from_label": "Network",
            "to_label": "Service",
            "evidence_mode": "configured",
            "source": "fixture",
            "freshness": "fresh",
            "collected_at": "2026-01-01T00:00:00+00:00",
            "maturity": "fixture_tested",
            "confidence": "stated",
        }
    })
    assert steps[0]["relationship"] == "routes_to"
    assert steps[0]["evidence_state"] == "Configured"
    assert "packet delivery" in steps[0]["limitation"]
