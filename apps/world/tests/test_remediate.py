from __future__ import annotations

import json

import pytest

from threatsight_world import cli, evidence as ev
from threatsight_world import remediate as rem
from threatsight_world.assess import ScriptedProvider
from threatsight_world.scenarios import CLOUD, PAYMENT, SCENARIOS
from threatsight_world.variants import variants_for

EMPTY = {"name": "t", "rules": []}


class FakeModel:
    """Answers complete_json with pre-written texts, in order, and keeps what it was asked."""

    name = "fake"

    def __init__(self, *answers: str | Exception) -> None:
        self.answers = list(answers)
        self.asked: list[list[dict]] = []
        self.temperatures: list[float] = []
        self.schemas: list[dict | None] = []

    def complete_json(self, messages, temperature=0.0, schema=None):
        self.asked.append(messages)
        self.schemas.append(schema)
        self.temperatures.append(temperature)
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


@pytest.fixture
def store(tmp_path):
    return rem.Store(tmp_path, "nordvik")


@pytest.mark.parametrize("sc", list(SCENARIOS.values()), ids=lambda s: s.id)
def test_heuristic_fix_is_proven_applied_and_post_checked(sc, tmp_path):
    store = rem.Store(tmp_path, sc.profile)
    p = rem.propose(sc, ScriptedProvider(), rem.HeuristicProposer(), store)
    assert p["status"] == "proposed", p["attempts"]
    assert p["proof"]["attack"]["before"]["FAIL"] == len(variants_for(sc)) and p["proof"]["attack"]["after"]["FAIL"] == 0
    assert all(u["passed"] for u in p["proof"]["utility"])
    assert store.head() == 0, "proposing must never change the live policy"
    p = rem.apply(store, p["id"], "Kari Approver", ScriptedProvider(), SCENARIOS)
    assert p["status"] == "applied" and p["history"][-1]["post_check"]["verdict"] == "PASS"
    assert [r["id"] for r in store.current()["rules"]] == [p["rule"]["id"]]
    assert ev.verify_records(ev.load(store.evidence_path(p["id"])))[0]


def test_rollback_writes_a_new_version_with_the_rule_removed(store):
    p = rem.propose(PAYMENT, ScriptedProvider(), rem.HeuristicProposer(), store)
    rem.apply(store, p["id"], "A. Person", ScriptedProvider(), SCENARIOS)
    p = rem.rollback(store, p["id"], "A. Person")
    assert p["status"] == "rolled_back"
    assert store.head() == 2 and store.current()["rules"] == []
    v1, v2 = store.versions()
    assert v1["inverse"] == {"op": "remove_rule", "rule_id": p["rule"]["id"]}
    assert v2["parent"] == 1 and v2["change"]["op"] == "remove_rule" and v2["diff"][0].startswith("- ")
    kinds = [r["kind"] for r in ev.load(store.evidence_path(p["id"]))]
    assert kinds[-4:] == ["approved", "applied", "post_check", "rolled_back"]


def test_failed_post_check_rolls_back_on_its_own(store):
    p = rem.propose(PAYMENT, ScriptedProvider(), rem.HeuristicProposer(), store)
    # Swap in a rule that does not stop the attack, as if the world had changed since the proof.
    p["rule"] = rem.validate({"rule_type": "max_amount_without_approver", "tool": "approve_payment", "limit": 1_000_000}, PAYMENT, EMPTY)
    (store.dir / "proposals" / f"{p['id']}.json").write_text(json.dumps(p))
    p = rem.apply(store, p["id"], "A. Person", ScriptedProvider(), SCENARIOS)
    assert p["status"] == "rolled_back" and p["history"][-1]["by"] == "post-check"
    assert store.head() == 2 and store.current()["rules"] == []


def test_apply_needs_a_named_approver_and_a_fresh_base(store, monkeypatch):
    a = rem.propose(PAYMENT, ScriptedProvider(), rem.HeuristicProposer(), store)
    b = rem.propose(CLOUD, ScriptedProvider(), rem.HeuristicProposer(), store)
    with pytest.raises(rem.RemediationError, match="approver"):
        rem.apply(store, a["id"], "  ", ScriptedProvider(), SCENARIOS)
    monkeypatch.setenv(rem.KILL_SWITCH, "1")
    with pytest.raises(rem.RemediationError, match="switched off"):
        rem.apply(store, a["id"], "A. Person", ScriptedProvider(), SCENARIOS)
    monkeypatch.delenv(rem.KILL_SWITCH)
    rem.apply(store, a["id"], "A. Person", ScriptedProvider(), SCENARIOS)
    with pytest.raises(rem.RemediationError, match="moved from version 0 to 1"):
        rem.apply(store, b["id"], "A. Person", ScriptedProvider(), SCENARIOS)
    with pytest.raises(rem.RemediationError, match="not proposed"):
        rem.apply(store, a["id"], "A. Person", ScriptedProvider(), SCENARIOS)


def test_reject_closes_the_proposal_without_touching_the_policy(store):
    p = rem.propose(PAYMENT, ScriptedProvider(), rem.HeuristicProposer(), store)
    p = rem.reject(store, p["id"], "A. Person", "call the supplier first")
    assert p["status"] == "rejected" and store.head() == 0


def test_nothing_to_fix_when_the_policy_already_holds(store):
    rem.apply(store, rem.propose(PAYMENT, ScriptedProvider(), rem.HeuristicProposer(), store)["id"], "A", ScriptedProvider(), SCENARIOS)
    p = rem.propose(PAYMENT, ScriptedProvider(), rem.HeuristicProposer(), store)
    assert p["status"] == "nothing_to_fix" and p["attempts"] == []


@pytest.mark.parametrize("raw, match", [
    ({"rule_type": "run_shell", "tool": "approve_payment"}, "not in the catalog"),
    ({"rule_type": "internal_recipients_only", "tool": "cloud_admin"}, "not one of this agent's tools"),
    ({"rule_type": "requester_owns_case", "tool": "approve_payment"}, "cannot guard"),
    ({"rule_type": "supplier_registered", "tool": "approve_payment", "on_fail": "allow"}, "on_fail"),
    ({"rule_type": "supplier_registered", "tool": "approve_payment", "script": "rm -rf /"}, "unexpected keys"),
    ({"rule_type": "max_amount_without_approver", "tool": "approve_payment", "limit": "50000"}, "limit must be a number"),
    ({"rule_type": "max_amount_without_approver", "tool": "approve_payment", "limit": -1}, "limit must be a number"),
    ([], "JSON object"),
])
def test_validate_rejects_anything_outside_the_catalog(raw, match):
    with pytest.raises(rem.ProposalError, match=match):
        rem.validate(raw, PAYMENT, EMPTY)


@pytest.mark.parametrize("actions, match", [
    (["list_backups", "read_logs", "set_bucket_acl", "delete_backup"], "guards nothing"),
    (["list_backups", "format_disk"], "unknown actions"),
    ([], "non-empty"),
])
def test_validate_checks_allow_actions(actions, match):
    with pytest.raises(rem.ProposalError, match=match):
        rem.validate({"rule_type": "allow_actions", "tool": "cloud_admin", "actions": actions}, CLOUD, EMPTY)


def test_validate_sets_the_amount_argument_and_id_itself():
    rule = rem.validate({"rule_type": "max_amount_without_approver", "tool": "issue_refund", "limit": 5000, "on_fail": "hold", "reason": "x"},
                        SCENARIOS["helio-refund-redirect"], EMPTY)
    assert rule["amount_arg"] == "amount_eur" and rule["id"] == "fix-issue-refund-max-amount-without-approver"


def test_validate_refuses_a_duplicate_rule():
    rule = rem.validate({"rule_type": "supplier_registered", "tool": "approve_payment"}, PAYMENT, EMPTY)
    with pytest.raises(rem.ProposalError, match="already has"):
        rem.validate({"rule_type": "supplier_registered", "tool": "approve_payment"}, PAYMENT, {"rules": [rule]})


def test_model_answers_are_validated_and_proven_and_rejections_are_fed_back(store):
    model = FakeModel(
        "Sure! I would add a firewall.",                                                              # not JSON
        json.dumps({"rule_type": "max_amount_without_approver", "tool": "approve_payment", "limit": 1e9}),  # valid, but does not stop it
        "```json\n" + json.dumps({"rule_type": "supplier_registered", "tool": "approve_payment", "on_fail": "hold", "reason": "new account"}) + "\n```",
    )
    p = rem.propose(PAYMENT, ScriptedProvider(), rem.ModelProposer(model), store)
    assert p["status"] == "proposed" and p["rule"]["type"] == "supplier_registered"
    whys = [a["why"] for a in p["attempts"]]
    assert "not JSON" in whys[0] and "still cause harm" in whys[1]
    last = json.loads(model.asked[-1][1]["content"])
    assert len(last["already_rejected"]) == 2
    assert {c["rule_type"] for c in last["catalog"]} >= {"supplier_registered", "max_amount_without_approver", "internal_recipients_only"}


def test_a_fix_that_breaks_routine_work_is_not_proven(store):
    model = FakeModel(json.dumps({"rule_type": "allow_actions", "tool": "cloud_admin", "actions": ["read_logs"]}))
    p = rem.propose(CLOUD, ScriptedProvider(), rem.ModelProposer(model), rem.Store(store.dir.parent, "nordvik"), max_candidates=1)
    assert p["status"] == "no_proven_fix" and "List backups" in p["attempts"][0]["why"]


def test_model_down_leaves_the_finding_open(store):
    p = rem.propose(PAYMENT, ScriptedProvider(), rem.ModelProposer(FakeModel(ConnectionError("refused"))), store)
    assert p["status"] == "no_proven_fix" and "unavailable" in p["attempts"][0]["why"] and store.head() == 0


def test_cli_propose_apply_rollback(tmp_path, capsys):
    assert cli.main(["remediate", "propose", "cross-citizen-record", "--store", str(tmp_path), "--json"]) == 0
    pid = json.loads(capsys.readouterr().out)["id"]
    assert cli.main(["remediate", "apply", pid, "--approver", "A. Person", "--store", str(tmp_path)]) == 0
    assert cli.main(["remediate", "rollback", pid, "--approver", "A. Person", "--store", str(tmp_path)]) == 0
    assert cli.main(["remediate", "rollback", pid, "--approver", "A. Person", "--store", str(tmp_path)]) == 4
    assert cli.main(["remediate", "status", "--store", str(tmp_path)]) == 0
    assert "v2" in capsys.readouterr().out


def test_parameters_a_rule_type_does_not_use_are_dropped_not_obeyed():
    """qwen2.5:7b-instruct sent limit and actions on every answer; they must not reach the rule."""
    rule = rem.validate({"rule_type": "requester_owns_case", "tool": "lookup_case", "on_fail": "hold", "limit": 0, "actions": ["send_email"]},
                        SCENARIOS["cross-citizen-record"], EMPTY)
    assert "limit" not in rule and "actions" not in rule and rule["type"] == "requester_owns_case"
    rule = rem.validate({"rule_type": "max_amount_without_approver", "tool": "approve_payment", "on_fail": "hold", "limit": 450000, "actions": ["send_email"]}, PAYMENT, EMPTY)
    assert rule["limit"] == 450000 and "actions" not in rule


def test_block_actions_becomes_the_allow_list():
    """qwen read allow_actions as 'the actions to stop'; the proposer now names what to block."""
    rule = rem.validate({"rule_type": "allow_actions", "tool": "cloud_admin", "on_fail": "deny", "block_actions": ["set_bucket_acl", "delete_backup"]}, CLOUD, EMPTY)
    assert rule["actions"] == ["list_backups", "read_logs"]
    with pytest.raises(rem.ProposalError, match="every action"):
        rem.validate({"rule_type": "allow_actions", "tool": "cloud_admin", "block_actions": rem.TOOL_ACTIONS["cloud_admin"]["all"]}, CLOUD, EMPTY)
    with pytest.raises(rem.ProposalError, match="unknown actions"):
        rem.validate({"rule_type": "allow_actions", "tool": "cloud_admin", "block_actions": ["format_disk"]}, CLOUD, EMPTY)
    with pytest.raises(rem.ProposalError, match="needs block_actions"):
        rem.validate({"rule_type": "allow_actions", "tool": "cloud_admin", "block_actions": [], "actions": []}, CLOUD, EMPTY)


def test_retries_are_not_replayed_twice_and_use_some_randomness(store):
    bad = json.dumps({"rule_type": "allow_actions", "tool": "cloud_admin", "on_fail": "deny", "block_actions": ["list_backups", "set_bucket_acl", "delete_backup"]})
    good = json.dumps({"rule_type": "allow_actions", "tool": "cloud_admin", "on_fail": "deny", "block_actions": ["set_bucket_acl", "delete_backup"], "limit": None})
    model = FakeModel(bad, bad, good)
    p = rem.propose(CLOUD, ScriptedProvider(), rem.ModelProposer(model), store)
    assert p["status"] == "proposed", p["attempts"]
    assert "List backups" in p["attempts"][0]["why"] and p["attempts"][1]["why"].startswith("same rule as an earlier candidate")
    assert p["attempts"][1]["proof"] is None
    assert model.temperatures == [0.0, 0.7, 0.7]


def test_the_answer_schema_only_offers_this_agents_tools_and_rules(store):
    model = FakeModel(json.dumps({"rule_type": "supplier_registered", "tool": "approve_payment", "on_fail": "hold", "reason": "x"}))
    rem.propose(PAYMENT, ScriptedProvider(), rem.ModelProposer(model), store)
    schema = model.schemas[0]
    shapes = schema["anyOf"]
    assert all(sh["additionalProperties"] is False for sh in shapes)
    assert {t for sh in shapes for t in sh["properties"]["tool"]["enum"]} <= set(PAYMENT.tools)
    types = {sh["properties"]["rule_type"]["enum"][0]: sh for sh in shapes}
    assert "requester_owns_case" not in types and all("block_actions" not in sh["properties"] for sh in shapes)
    assert "limit" in types["max_amount_without_approver"]["required"], "models left limit out when it was optional"
    cloud = rem.answer_schema(CLOUD.tools)
    assert cloud["properties"]["rule_type"]["enum"] == ["allow_actions"] and "block_actions" in cloud["required"]
    assert "set_bucket_acl" in cloud["properties"]["block_actions"]["items"]["enum"]


def test_the_model_is_told_every_action_the_control_forbids(store):
    """Bake-off: all three models blocked set_bucket_acl but kept delete_backup on helio-runbook-injection."""
    assert rem.hostile_actions(SCENARIOS["helio-runbook-injection"]) == {"cloud_admin": ["set_bucket_acl", "delete_backup"]}
    model = FakeModel(json.dumps({"rule_type": "allow_actions", "tool": "cloud_admin", "on_fail": "deny", "block_actions": ["set_bucket_acl", "delete_backup"], "reason": "x"}))
    p = rem.propose(CLOUD, ScriptedProvider(), rem.ModelProposer(model), store)
    assert json.loads(model.asked[0][1]["content"])["actions_the_control_forbids"] == {"cloud_admin": ["set_bucket_acl", "delete_backup"]}
    assert p["status"] == "proposed"


def test_complete_json_falls_back_when_the_server_refuses_json_schema():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from threatsight_world.llm import OpenAICompatModel

    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(body["response_format"]["type"])
            if body["response_format"]["type"] == "json_schema":
                self.send_response(400)
                self.end_headers()
                return
            out = json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        m = OpenAICompatModel(f"http://127.0.0.1:{httpd.server_address[1]}/v1", "m")
        assert m.complete_json([{"role": "user", "content": "x"}], schema={"type": "object"}) == "{}"
        assert seen == ["json_schema", "json_object"]
    finally:
        httpd.shutdown()


def test_an_allow_list_that_leaves_another_hostile_action_open_is_not_proven(store):
    """Found in the bake-off: blocking set_bucket_acl but not delete_backup passed the scripted replay."""
    half = json.dumps({"rule_type": "allow_actions", "tool": "cloud_admin", "on_fail": "deny", "block_actions": ["set_bucket_acl"], "reason": "x"})
    full = json.dumps({"rule_type": "allow_actions", "tool": "cloud_admin", "on_fail": "deny", "block_actions": ["set_bucket_acl", "delete_backup"], "reason": "x"})
    p = rem.propose(CLOUD, ScriptedProvider(), rem.ModelProposer(FakeModel(half, full)), store)
    assert "can still run delete_backup" in p["attempts"][0]["why"]
    assert p["status"] == "proposed" and p["rule"]["actions"] == ["list_backups", "read_logs"]
