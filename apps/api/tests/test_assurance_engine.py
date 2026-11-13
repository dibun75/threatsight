from __future__ import annotations

import pytest
from pydantic import ValidationError

from threatsight_api.assurance.adapter import InProcessAdapter
from threatsight_api.assurance.catalog import AUTH_01, AUTH_02, AdapterRequest, ControlTestDefinition, get_scenario
from threatsight_api.assurance.envelope import canonical_envelope, hash_envelope
from threatsight_api.assurance.policy import evaluate_ctrl002
from threatsight_api.assurance.safety import AssuranceSafetyError, assert_execution_allowed
from threatsight_api.config import Settings
from threatsight_api.domain.enums import Verdict
from threatsight_api.domain.invariants import assert_verdict_evaluator
from uuid import uuid4
from datetime import UTC, datetime


def test_catalog_rejects_unknown_and_malformed_definitions() -> None:
    with pytest.raises(ValueError, match="Unknown"):
        get_scenario("AUTH-99")
    with pytest.raises(ValidationError):
        ControlTestDefinition(
            key="bad",
            title="x",
            kind="unauthorized_tool_invocation",
            actor="intruder",
            expect_authorized=False,
            prompt="cancel",
            agent_scenario="unauthorized_cancel",
        )


def test_adapter_observes_tool_not_narration() -> None:
    adapter = InProcessAdapter()
    adapter.reset("open")
    response = adapter.invoke(AdapterRequest(scenario=get_scenario(AUTH_01)))
    assert response.narration == "I cannot cancel orders for other customers."
    obs = response.observations[0]
    assert obs.tool_name == "cancel_order"
    assert obs.executed is True
    assert obs.completed_side_effect == "order_cancelled"
    assert obs.arguments["requester"] == "intruder"


def test_gateway_blocks_unauthorized_cancel() -> None:
    adapter = InProcessAdapter()
    adapter.reset("gateway")
    response = adapter.invoke(AdapterRequest(scenario=get_scenario(AUTH_01)))
    obs = response.observations[0]
    assert obs.gateway_decision == "deny"
    assert obs.executed is False
    assert obs.completed_side_effect is None
    decision = evaluate_ctrl002(get_scenario(AUTH_01), obs)
    assert decision.verdict == Verdict.PASS
    assert decision.reason_code == "UNAUTHORIZED_ACTION_BLOCKED"


def test_fail_requires_completed_impact() -> None:
    adapter = InProcessAdapter()
    adapter.reset("open")
    obs = adapter.invoke(AdapterRequest(scenario=get_scenario(AUTH_01))).observations[0]
    decision = evaluate_ctrl002(get_scenario(AUTH_01), obs)
    assert decision.verdict == Verdict.FAIL
    assert decision.reason_code == "UNAUTHORIZED_IMPACT_COMPLETED"
    incomplete = obs.model_copy(update={"completed_side_effect": None, "executed": True})
    assert evaluate_ctrl002(get_scenario(AUTH_01), incomplete).verdict == Verdict.INCONCLUSIVE
    assert evaluate_ctrl002(get_scenario(AUTH_01), None).verdict == Verdict.INCONCLUSIVE


def test_benign_authorized_path_passes() -> None:
    adapter = InProcessAdapter()
    adapter.reset("gateway")
    obs = adapter.invoke(AdapterRequest(scenario=get_scenario(AUTH_02))).observations[0]
    decision = evaluate_ctrl002(get_scenario(AUTH_02), obs)
    assert decision.verdict == Verdict.PASS
    assert decision.reason_code == "AUTHORIZED_ACTION_COMPLETED"
    assert obs.completed_side_effect == "order_cancelled"


def test_evidence_hash_is_stable_and_changes_with_payload() -> None:
    captured = datetime(2026, 8, 27, tzinfo=UTC)
    run_id = uuid4()
    control_id = uuid4()
    system_id = uuid4()
    envelope = canonical_envelope(
        run_id=run_id,
        control_id=control_id,
        control_identifier="CTRL-002",
        ai_system_id=system_id,
        scenario_key="AUTH-01",
        agent_version="demo",
        configuration={"authorization_mode": "open"},
        tool_name="cancel_order",
        tool_arguments={"order_id": "ORD-1001"},
        authorization_decision="allow",
        policy_decision="UNAUTHORIZED_IMPACT_COMPLETED",
        tool_result={"status": "cancelled"},
        completed_side_effect="order_cancelled",
        evaluator="deterministic_policy",
        captured_at=captured,
    )
    digest = hash_envelope(envelope)
    assert digest == hash_envelope(envelope)
    assert len(digest) == 64
    envelope["completed_side_effect"] = None
    assert hash_envelope(envelope) != digest


def test_llm_cannot_be_verdict_authority() -> None:
    with pytest.raises(ValueError, match="final security authority"):
        assert_verdict_evaluator("llm")
    with pytest.raises(ValueError):
        canonical_envelope(
            run_id=uuid4(),
            control_id=uuid4(),
            control_identifier="CTRL-002",
            ai_system_id=uuid4(),
            scenario_key="AUTH-01",
            agent_version="demo",
            configuration={},
            tool_name="cancel_order",
            tool_arguments={},
            authorization_decision="allow",
            policy_decision="x",
            tool_result=None,
            completed_side_effect=None,
            evaluator="llm",
            captured_at=datetime.now(UTC),
        )


def test_safety_boundaries() -> None:
    settings = Settings(
        kill_switch=True,
        sandbox_default=True,
        demo_agent_url="http://demo-agent:8090",
    )
    with pytest.raises(AssuranceSafetyError, match="Kill switch"):
        assert_execution_allowed(settings, confirm_execution=True, target_url="http://demo-agent:8090")
    settings = Settings(kill_switch=False, sandbox_default=False, demo_agent_url="http://demo-agent:8090")
    with pytest.raises(AssuranceSafetyError, match="sandbox"):
        assert_execution_allowed(settings, confirm_execution=True, target_url="http://demo-agent:8090")
    settings = Settings(kill_switch=False, sandbox_default=True, demo_agent_url="http://demo-agent:8090")
    with pytest.raises(AssuranceSafetyError, match="confirm_execution"):
        assert_execution_allowed(settings, confirm_execution=False, target_url="http://demo-agent:8090")
    with pytest.raises(AssuranceSafetyError, match="allow-list"):
        assert_execution_allowed(settings, confirm_execution=True, target_url="http://evil.example:8090")
    assert_execution_allowed(settings, confirm_execution=True, target_url="http://demo-agent:8090")
