from __future__ import annotations

import json

from threatsight_world import graph
from threatsight_world.policy import Gateway
from threatsight_world.scenarios import SCENARIOS, scenarios_for
from threatsight_world.tools import TOOLS

OPEN = Gateway(None)
HARD = Gateway.from_name("nordvik-hardened")


def test_graph_is_derived_from_the_scenarios_and_serialisable():
    g = graph.build_graph(OPEN)
    assert [a["id"] for a in g["agents"]] == [s.id for s in scenarios_for("nordvik")]
    helio = graph.build_graph(Gateway.from_name("helio-hardened"), "helio")
    assert [a["id"] for a in helio["agents"]] == [s.id for s in scenarios_for("helio")]
    assert all(t["guarded"] for a in helio["agents"] for t in a["tools"] if t["impact"] != "read")
    assert json.loads(json.dumps(g)) == g
    for a in g["agents"]:
        assert [t["name"] for t in a["tools"]] == SCENARIOS[a["id"]].tools


def test_every_tool_and_input_is_declared():
    for t in TOOLS:
        assert t in graph.TOOL_DATA
    assert set(graph.TOOL_DATA.values()) <= set(graph.DATA_SENSITIVITY)
    assert set(graph.AGENT_INPUTS) == set(SCENARIOS)


def test_open_gateway_has_no_guardrails_and_hardened_lowers_every_score():
    o, h = graph.build_graph(OPEN), graph.build_graph(HARD)
    for a, b in zip(o["agents"], h["agents"]):
        assert a["factors"]["guardrails"] == 0
        assert b["factors"]["guardrails"] == 100
        assert b["score"] < a["score"]
        assert 0 <= b["score"] <= a["score"] <= 100


def test_score_matches_the_documented_formula():
    a = next(x for x in graph.build_graph(OPEN)["agents"] if x["id"] == "payment-injection")
    f = a["factors"]
    assert a["score"] == round(0.50 * f["impact"] + 0.25 * f["sensitivity"] + 0.25 * f["reach"])
    assert a["worst_path"] == {"input": "Inbound email", "tool": "approve_payment", "data": "Finance ledger"}


def test_highest_impact_agents_rank_above_read_mostly_agents():
    scores = {a["id"]: a["score"] for a in graph.build_graph(OPEN)["agents"]}
    assert scores["cloud-ticket-acl"] > scores["cross-citizen-record"]
    assert scores["payment-injection"] > scores["document-injection"]


def test_cli_compare_runs(capsys):
    assert graph.main(["--compare"]) == 0
    assert "Procurement Bot" in capsys.readouterr().out
